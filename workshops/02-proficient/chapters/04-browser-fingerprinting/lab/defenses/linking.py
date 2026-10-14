"""
Chapter 4 — L3: Linking Accounts by Fingerprint (Section 4.5, Round 3)

The attacker has given up on lying. They replay one real, perfectly
consistent fingerprint for every sign-up and rotate IPs. L1 and L2 see an
honest Windows laptop. What gives them away is *reuse*: one device
creating many accounts.

    accounts already created today with this stable_id >= limit   +40  fingerprint_linked

The limit comes from population.py: 3 for a rare device, 10 for an
uncommon one, and no fingerprint-only limit for a common one (an iPhone or
a standard corporate laptop image). Run the demo site with LINK_MODE=naive
to see what happens without that: identical office laptops and identical
MacBooks start blocking each other.

The lookup (`fingerprint.accounts_today`) is one Redis sorted set per device,
scored by time:

    ZRANGEBYSCORE lab:fp:acct:<stable_id> <now - 24 h> +inf

That key is the index. In a SQL store the same rule is a `SELECT count(*) ...
WHERE stable_id = :sid AND created_at > now() - interval '24 hours'`, which
needs an index on (stable_id, created_at); without one it is the most
expensive thing the defense does. Here the cost shows up in the
`Server-Timing: linking;dur=...` header, and the checkpoint reports it.

Trade-off: linking only works if the ID is stable. Anything that adds noise
to a high-entropy component (canvas, audio) makes every sign-up look new.
That is Round 4.
"""

from . import fingerprint, policy
from .pipeline import Check
from .rarity import account_limit
from .stable_id import device_class, stable_id

LINK_POINTS = 40


def score_linking(fp, accounts_today, mode="rarity"):
    """
    Return (points, reasons).

    accounts_today(stable_id) -> the source IP of every account already
    created with that ID in the last 24 hours (fingerprint.accounts_today,
    backed by Redis): one entry per account.
    """
    sid, cls = stable_id(fp), device_class(fp)
    limit = account_limit(cls, mode)
    if limit is None:
        return 0, []
    ips = accounts_today(sid)
    existing = len(ips)
    # TODO (Round 3, optional tuning): a family sharing one laptop can legitimately create two
    # or three accounts. Count *distinct IPs* (`ips` holds one per account)
    # and only add points when the accounts came from more than one network.
    # This is optional tuning: the layer works as shipped. What does the
    # attacker do next?
    if existing >= limit:
        return LINK_POINTS, [f"fingerprint_linked: {existing} accounts today from device "
                             f"{sid} (limit {limit} for class {cls})"]
    return 0, []


def evaluate(ctx):
    """(points, reasons) for this session's record against the accounts created today."""
    return score_linking(fingerprint.record(ctx)["payload"], lambda sid: fingerprint.accounts_today(ctx, sid),
                         policy.LINK_MODE)


def _check(ctx):
    if fingerprint.record(ctx) is None:
        return None
    points, reasons = evaluate(ctx)
    return fingerprint.signals("L3", "fingerprint_linked", points, reasons, ctx)


CHECK = Check("linking", _check, phases=("action:register",))


if __name__ == '__main__':
    fp = {
        "nav": {"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...", "hardwareConcurrency": 16},
        "screen": {"width": 2560, "height": 1440, "devicePixelRatio": 1},
        "webgl": {"supported": True, "unmaskedRenderer":
                  "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)"},
    }
    for already in range(5):
        print(already, "existing →", score_linking(fp, lambda _sid: ["192.0.2.1"] * already))
