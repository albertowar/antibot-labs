"""
Cohort (population) features (Round 2)

Per-session features ask "does this session look human?". A bot author controls every one of
them. Cohort features ask "how many OTHER sessions look like this one right now?". Answering that
means controlling the whole population: one stealth profile reused 60 times is 60 human-looking
sessions, but it is also one fingerprint fanned out over dozens of addresses.

All counts use a sliding window of WINDOW_S *virtual* seconds that ends at the purchase attempt
(point-in-time correct, so no future leakage). The window is built two ways: offline from the
training history (`PopulationIndex`) and online from the store's Redis (`window_from_redis`), and
both hand `features()` the same rows.

The "network" is the exact source address. A production lab would use a /24 (IPv4) or /64 (IPv6),
but the RFC 5737 documentation ranges this series is limited to put every home user in one /24,
which would make the count meaningless.

False-positive profile, read before you trust these:
  - CGNAT mobile carriers put hundreds of real people behind one address, so `ip_sessions_1h` is
    high for them. Never use it alone.
  - Identical devices collide: same iPhone model + same locale = same fingerprint. A drop day with
    30 people on the same phone looks like a small farm on `fp_sessions_1h`. `fp_ip_fanout_1h`
    separates the two only when those people are on different networks.
  - Privacy browsers randomise canvas per session, so their fingerprints never repeat: cohort
    features say nothing about them either way.
"""

from bisect import bisect_right

import numpy as np

from demo_site.ext import ml_store

WINDOW_S = ml_store.WINDOW_S  # one virtual hour

COHORT_FEATURES = [
    "fp_sessions_1h",       # sessions sharing this exact fingerprint
    "fp_ip_fanout_1h",      # distinct addresses that fingerprint arrived from
    "ip_sessions_1h",       # sessions from this address
]


def _scale():
    from .features import LAB_TIME_SCALE
    return LAB_TIME_SCALE


class Window:
    """Population rows a session can match: sessions on its address (sid, ip), reports of its fingerprint (sid, fp_hash, ip)."""

    def __init__(self, sessions, fps):
        self.sessions = sessions
        self.fps = fps


class PopulationIndex:
    """Offline helper: slice the full history into point-in-time windows quickly."""

    def __init__(self, sessions, telemetry):
        self.by_ip, self.by_fp = {}, {}
        for s in sorted(sessions, key=lambda s: s["first_ts"]):
            self.by_ip.setdefault(s["ip"], []).append(s)
        for t in sorted((t for t in telemetry if t["kind"] == "fp"), key=lambda t: t["ts"]):
            self.by_fp.setdefault(t["fp_hash"], []).append(t)
        self._ip_ts = {k: [s["first_ts"] for s in v] for k, v in self.by_ip.items()}
        self._fp_ts = {k: [t["ts"] for t in v] for k, v in self.by_fp.items()}

    def window(self, as_of, ip, fp_hash):
        start = as_of - WINDOW_S * _scale()
        rows = self.by_ip.get(ip, [])
        ts = self._ip_ts.get(ip, [])
        sessions = rows[bisect_right(ts, start):bisect_right(ts, as_of)]
        fps = []
        if fp_hash:
            rows, ts = self.by_fp.get(fp_hash, []), self._fp_ts.get(fp_hash, [])
            fps = rows[bisect_right(ts, start):bisect_right(ts, as_of)]
        return Window(sessions, fps)


def window_from_redis(redis, as_of, ip, fp_hash):
    """Online helper: the same window, straight from the store's Redis (only the rows features() can match)."""
    sessions, fps = ml_store.window_rows(redis, as_of - WINDOW_S * _scale(), as_of, ip, fp_hash)
    return Window(sessions, fps)


def features(window, ip, fp_hash):
    """Cohort counts for one session (the window already ends at its purchase attempt)."""
    # TODO (Round 2): fill in the three COHORT_FEATURES from the window.
    #   window.sessions  rows {sid, ip}: sessions first seen on THIS address inside the window
    #   window.fps       rows {sid, fp_hash, ip}: reports of THIS fingerprint inside the window
    #   ip_sessions_1h   how many sessions came from `ip`
    #   fp_sessions_1h   how many distinct sessions reported this fingerprint
    #   fp_ip_fanout_1h  how many distinct addresses those reports came from
    # No fingerprint (fp_hash is None) means the client never ran JavaScript: the two fingerprint
    # counts are UNKNOWN (np.nan), not zero.
    # Then retrain (`python -m defenses.train --round 2`) and compare the holdout with --random-split.
    return {name: np.nan for name in COHORT_FEATURES}
