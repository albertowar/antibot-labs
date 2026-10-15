"""
Round 4 defense (level 4): score the verdict and the device's velocity.

Round 4's attacker cannot forge a verdict (Round 2) or replay one (Round 3), so they do the only thing left:
run the REAL app on an emulator or a rack of devices and mint many fresh, genuine, correctly bound verdicts.
Each one is individually valid. You stop the *fleet*, not the single request, with two signals:

  1. Integrity. An emulator or a tampered device cannot earn hardware-backed integrity. Score the strongest
     level the verdict carries (mobile_core.integrity_level): "strong" and "device" cost nothing, "basic" is
     friction, "none" is heavy. An app that is not a store build (appIntegrity) adds a little more.
  2. Velocity. One deviceId buying again and again, or many weak-integrity devices from one address in an
     hour, is a farm. Count per deviceId and per source address in Redis and add a block-sized signal past
     a threshold.

    verdict = ctx.attrs["attest"]       # deviceId, deviceIntegrity, appIntegrity (signature checked already)
    ctx.ip                              # the address the edge saw (a rented world.json address in this lab)
    ctx.redis                           # keep your keys under "lab:" so POST /lab/reset wipes them

>>> READ BEFORE YOU TUNE THIS: the integrity signal is exactly what hurts real users. A rooted power user, a
>>> GrapheneOS phone and a cheap uncertified Android all return weak integrity too. Tune so the FARM is blocked
>>> (verdict + velocity, 75 and up) while a lone weak device only reaches the challenge band (40 to 74). This
>>> store has no step-up flow behind the challenge band, so the gate enforces it as a refusal: the checkpoint
>>> lists those customers as the cost, and that bill is the point of the round.
>>> Catch up with:  python tools/checkpoint.py --round 4 --catch-up
"""

from .mobile_core import integrity_level  # noqa: F401
from .pipeline import Check, Signal  # noqa: F401

DEVICE_BUYS_PER_HOUR = 3
WEAK_DEVICES_PER_EGRESS_HOUR = 3


def _check(ctx):
    verdict = ctx.attrs.get("attest")
    if verdict is None:
        return None
    # TODO (Round 4): implement the integrity + velocity scoring described above.
    #   integrity_level(verdict): "strong" / "device" -> 0 points, "basic" -> 25, "none" -> 40
    #   verdict["appIntegrity"] != "PLAY_RECOGNIZED"  -> +10
    #   dev:<deviceId>:<hour> counter above DEVICE_BUYS_PER_HOUR            -> +80
    #   a set of weak deviceIds per address and hour above WEAK_DEVICES_PER_EGRESS_HOUR -> +80
    return None


CHECK = Check("device_verdict", _check, phases=("action:mobile_buy",))
