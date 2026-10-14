"""
Chapter 4 — L4: Fuzzy Clustering on Noise-Resistant Components (Section 4.6, Round 4)

The attacker's answer to L3 is noise, the same trick privacy browsers use:
a fresh canvas and audio hash on every sign-up, plus a little hardware
jitter. Every stable_id is new. L4 stops comparing IDs and compares
*components*:

  1. Drop the components that anyone can noise (canvas, audio, voices).
  2. Compare the remaining core components with each account created
     today. Two fingerprints are "the same device" when at least
     SIMILARITY_THRESHOLD of the components match. One field may differ
     (a jittered core count, a newly installed font).
  3. Apply the same rarity-weighted limit as L3 to the size of the cluster.

    similar accounts today >= limit   +40  fingerprint_cluster

Noise itself scores nothing. Brave, Firefox with fingerprinting
protection and Safari 26 add noise for every user, and so do privacy
extensions. "This canvas is randomised" tells you the user cares about
privacy, not that they are a bot. We record it, drop the noised components
and move on.

Cost: a linear scan over today's accounts, which is fine for a lab and
far too slow at scale. Production systems bucket candidates first
(locality-sensitive hashing over the components, or one index per
component) and only compare inside a bucket.

Trade-off: lower entropy means more real users collide. The rarity limit
is what keeps an office full of identical laptops from being clustered
into one "bot".
"""

from . import fingerprint, policy
from .pipeline import Check
from .rarity import account_limit
from .stable_id import core_components, device_class

CLUSTER_POINTS = 40
SIMILARITY_THRESHOLD = 0.9


def similarity(a, b):
    """Share of core components that are equal (missing == missing counts as equal)."""
    keys = set(a) | set(b)
    if not keys:
        return 0.0
    return sum(a.get(k) == b.get(k) for k in keys) / len(keys)


def noise_markers(fp):
    """What kind of randomisation (if any) the payload shows. Informational only."""
    canvas = fp.get("canvas") or {}
    markers = []
    if canvas.get("supported") and canvas.get("hash") != canvas.get("hash2"):
        markers.append("canvas changes between two identical draws (per-call noise)")
    if (canvas.get("probeChangedPixels") or 0) > 0:
        markers.append(f"known-colour probe altered ({canvas['probeChangedPixels']}/64 pixels)")
    return markers


def score_cluster(fp, recent_cores, mode="rarity"):
    """
    Return (points, reasons).

    recent_cores() -> list of core-component dicts for accounts created in
    the last 24 hours (fingerprint.recent_cores, backed by Redis).
    """
    reasons = [f"note: {m}" for m in noise_markers(fp)]
    cls = device_class(fp)
    limit = account_limit(cls, mode)
    if limit is None:
        return 0, reasons
    mine = core_components(fp)
    # TODO (Round 4, optional tuning): weight the components instead of counting them.
    # A matching font list is much stronger evidence than a matching timezone.
    similar = sum(similarity(mine, other) >= SIMILARITY_THRESHOLD for other in recent_cores())
    if similar >= limit:
        reasons.append(f"fingerprint_cluster: {similar} accounts today from near-identical "
                       f"devices (limit {limit} for class {cls})")
        return CLUSTER_POINTS, reasons
    return 0, reasons


def evaluate(ctx):
    """(points, reasons) for this session's record against the cores of the accounts created today."""
    return score_cluster(fingerprint.record(ctx)["payload"], lambda: fingerprint.recent_cores(ctx),
                         policy.LINK_MODE)


def _check(ctx):
    if fingerprint.record(ctx) is None:
        return None
    points, reasons = evaluate(ctx)
    return fingerprint.signals("L4", "fingerprint_cluster", points, reasons, ctx)


CHECK = Check("fuzzy_cluster", _check, phases=("action:register",))


if __name__ == '__main__':
    import json
    import os
    with open(os.path.join(os.path.dirname(__file__), "..", "attacks", "data", "harvested_fp.json")) as f:
        harvested = json.load(f)["payload"]
    base = core_components(harvested)
    jittered = {**base, "cores": 12}
    two_fields = {**jittered, "screen": "1920x1080"}
    other = {**base, "gpu": "Intel(R) UHD Graphics 620", "screen": "1920x1080", "cores": 8, "timezone": "Europe/London"}
    print(f"{len(base)} core components, threshold {SIMILARITY_THRESHOLD}")
    for name, c in [("same device, cores jittered", jittered), ("cores + screen jittered", two_fields),
                    ("a different laptop", other)]:
        s = similarity(base, c)
        print(f"  {name:<28} similarity {s:.2f} -> {'same cluster' if s >= SIMILARITY_THRESHOLD else 'different'}")
