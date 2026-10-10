"""
Chapter 7 — Cohort (population) features (Round 2, Section 7.3)

Per-session features ask "does this session look human?". A bot author
controls every one of them. Cohort features ask "how many OTHER sessions
look like this one right now?". Answering that means controlling the whole
population: one stealth profile reused 60 times is 60 human-looking
sessions, but it is also one fingerprint fanned out over 60 IPs.

All counts use a sliding window of WINDOW_S *virtual* seconds that ends at
the session's checkout (point-in-time correct, so no future leakage).

False-positive profile, read before you trust these:
  - CGNAT mobile carriers put hundreds of real people behind one /24, so
    `ip24_sessions_1h` is high for them. Never use it alone.
  - Identical devices collide: same iPhone model + same locale = same
    fingerprint. A drop day with 30 people on the same phone looks like a
    small farm on `fp_sessions_1h`. `fp_ip24_fanout_1h` separates the two
    only when those people are on different networks.
  - Privacy browsers randomise canvas per session, so their fingerprints
    never repeat: cohort features say nothing about them either way.
"""

import os
import sys
from bisect import bisect_right

import numpy as np
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(__file__))

from netinfo import ip24  # noqa: E402
from store import LAB_TIME_SCALE  # noqa: E402

WINDOW_S = 3600  # one virtual hour

COHORT_FEATURES = [
    "fp_sessions_1h",       # sessions sharing this exact fingerprint
    "fp_ip24_fanout_1h",    # distinct /24s that fingerprint arrived from
    "ip24_sessions_1h",     # sessions from this /24
    # TODO (Round 2): add a cohort feature of your own, e.g. sessions that
    # followed the exact same page sequence. Add it here, compute it in
    # features() below, retrain with `python defenses/train.py --round 2`.
]


class Window:
    """Population rows inside one window: sessions (sid, ip) and fingerprints (sid, fp_hash, ip)."""

    def __init__(self, sessions, fps):
        self.sessions = sessions
        self.fps = fps


class PopulationIndex:
    """Offline helper: slice the full history into point-in-time windows quickly."""

    def __init__(self, sessions, telemetry):
        self.sessions = sorted(sessions, key=lambda s: s["first_ts"])
        self.fps = sorted((t for t in telemetry if t["kind"] == "fp"), key=lambda t: t["ts"])
        self._s_ts = [s["first_ts"] for s in self.sessions]
        self._f_ts = [t["ts"] for t in self.fps]

    def window(self, as_of):
        start = as_of - WINDOW_S * LAB_TIME_SCALE
        s0, s1 = bisect_right(self._s_ts, start), bisect_right(self._s_ts, as_of)
        f0, f1 = bisect_right(self._f_ts, start), bisect_right(self._f_ts, as_of)
        return Window(self.sessions[s0:s1], self.fps[f0:f1])


def window_from_db(conn, as_of, ip, fp_hash):
    """
    Online helper: the same window, straight from the database. Only the rows
    features() can match are fetched (same /24, same fingerprint), which keeps
    the query cost flat as traffic grows. Same features() code either way.
    """
    span = {"start": as_of - WINDOW_S * LAB_TIME_SCALE, "end": as_of,
            "ip24": ip24(ip) if ip else "", "fp": fp_hash or ""}
    sessions = conn.execute(text("SELECT sid, ip FROM sessions WHERE ip24 = :ip24 "
                                 "AND first_ts > :start AND first_ts <= :end"), span).mappings()
    fps = conn.execute(text("SELECT sid, fp_hash, ip FROM telemetry WHERE fp_hash = :fp "
                            "AND ts > :start AND ts <= :end"), span).mappings()
    return Window([dict(r) for r in sessions], [dict(r) for r in fps])


def features(window, ip, fp_hash):
    """Cohort counts for one session (the window already ends at its checkout)."""
    my24 = ip24(ip) if ip else None
    f = {"ip24_sessions_1h": sum(1 for s in window.sessions if ip24(s["ip"]) == my24)}
    if fp_hash is None:
        # No JS, no fingerprint: unknown rather than zero
        f["fp_sessions_1h"] = np.nan
        f["fp_ip24_fanout_1h"] = np.nan
        return f
    same = [t for t in window.fps if t["fp_hash"] == fp_hash]
    f["fp_sessions_1h"] = len({t["sid"] for t in same})
    f["fp_ip24_fanout_1h"] = len({ip24(t["ip"]) for t in same})
    return f
