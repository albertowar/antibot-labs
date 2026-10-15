"""
Streaming feature store: per-session state and global sketches.

A streaming detector cannot re-read the whole log for every event. It keeps a small amount of
state per key and updates it in O(1) as each event arrives. This module holds the two kinds of
state the detectors share, so there is one update path:

  SessionFeatures  per-session rolling features in a Redis hash: counts, a "bought" flag, and
                   Welford's online variance of inter-arrival gaps (timing regularity in O(1)
                   memory, never storing the gaps themselves).

  Sketches         global, sublinear-memory aggregates that would be far too expensive as exact
                   sets at scale:
                   - Count-Min    failed-login velocity per endpoint
                   - HyperLogLog  distinct source IPs (globally, and per account)
                   - Top-K        the heaviest endpoints, for the operator's report

Every sketch key carries a time *bucket* ((ts - epoch) // window) and a TTL, so a new window
starts a fresh sketch. The rate window is short, the per-account window is long, because
low-and-slow only shows up when you look back far enough. Lab windows are production windows
divided down (see streamlog.py); the epoch makes the buckets tumble from the first event.

All state lives in Redis under `lab:stream:`. Nothing is kept in the consumer's memory, so a
second consumer in the group sees the same state and a store reset leaves nothing behind.
"""

import math

from . import streamlog

WINDOW_RATE = 10        # seconds, per-IP request rate (sliding; production: 60)
WINDOW_VELOCITY = 60    # seconds, endpoint failed-login velocity (tumbling; production: 600)
WINDOW_CROSS = 120      # seconds, distinct-IP fan-out per account (tumbling; production: 3600)

PREFIX = streamlog.PREFIX


class SessionFeatures:
    """Per-session rolling features, updated once per event."""

    def __init__(self, r):
        self.r = r

    def update(self, event):
        """Fold one event into the session's state and return its features."""
        sid, ts = event["sid"], float(event["ts"])
        key = f"{PREFIX}sess:{sid}"
        h = self.r.hgetall(key)

        n = int(h.get("n", 0)) + 1
        n_fail = int(h.get("n_fail", 0)) + (1 if event.get("login_failed") == "1" else 0)
        n_page = int(h.get("n_page", 0)) + (1 if event.get("page") == "1" else 0)
        bought = h.get("bought", "0") == "1" or event.get("bought") == "1"
        first_ts = float(h.get("first_ts", ts))
        last_ts = float(h["last_ts"]) if "last_ts" in h else None

        # Welford online variance of inter-arrival gaps (O(1) memory).
        w_n, w_mean, w_m2 = int(h.get("w_n", 0)), float(h.get("w_mean", 0.0)), float(h.get("w_m2", 0.0))
        if last_ts is not None:
            gap = ts - last_ts
            w_n += 1
            delta = gap - w_mean
            w_mean += delta / w_n
            w_m2 += delta * (gap - w_mean)

        self.r.hset(key, mapping={
            "n": n, "n_fail": n_fail, "n_page": n_page, "bought": "1" if bought else "0",
            "first_ts": first_ts, "last_ts": ts, "w_n": w_n, "w_mean": w_mean, "w_m2": w_m2})
        self.r.expire(key, WINDOW_CROSS)

        cv = None
        if w_n >= 2 and w_mean > 0:
            cv = math.sqrt(w_m2 / (w_n - 1)) / w_mean
        return {"sid": sid, "ip": event["ip"], "user": event.get("user", ""), "n": n, "n_fail": n_fail,
                "n_page": n_page, "bought": bought, "cv": cv, "w_n": w_n, "duration_s": ts - first_ts}


class Sketches:
    """Global probabilistic aggregates in sublinear memory."""

    def __init__(self, r, epoch):
        self.r, self.epoch = r, epoch

    def _bucket(self, kind, ts, window, *parts):
        b = int((float(ts) - self.epoch) // window)
        tail = ":".join(str(p) for p in parts)
        return f"{PREFIX}{kind}:{b}" + (f":{tail}" if tail else "")

    # --- Count-Min: approximate endpoint failed-login velocity ---
    def bump_endpoint_fail(self, path, ts):
        key = self._bucket("cms", ts, WINDOW_VELOCITY)
        try:
            self.r.execute_command("CMS.INCRBY", key, path, 1)
        except Exception:
            self.r.execute_command("CMS.INITBYPROB", key, "0.001", "0.01")
            self.r.execute_command("CMS.INCRBY", key, path, 1)
        self.r.expire(key, WINDOW_VELOCITY)

    def endpoint_fail_rate(self, path, ts):
        try:
            return int(self.r.execute_command("CMS.QUERY", self._bucket("cms", ts, WINDOW_VELOCITY), path)[0])
        except Exception:
            return 0

    # --- Top-K: name the heaviest endpoints (for the report, not the verdict) ---
    def bump_topk_endpoint(self, path, ts):
        key = self._bucket("topk", ts, WINDOW_VELOCITY)
        try:
            self.r.execute_command("TOPK.ADD", key, path)
        except Exception:
            self.r.execute_command("TOPK.RESERVE", key, 8)
            self.r.execute_command("TOPK.ADD", key, path)
        self.r.expire(key, WINDOW_VELOCITY)

    def topk_endpoints(self, ts):
        try:
            return sorted(set(self.r.execute_command("TOPK.LIST", self._bucket("topk", ts, WINDOW_VELOCITY))))
        except Exception:
            return []

    # --- HyperLogLog: distinct source IPs failing login, globally and per account ---
    def add_fail_ip(self, ip, ts):
        key = self._bucket("hll_failip", ts, WINDOW_VELOCITY)
        self.r.pfadd(key, ip)
        self.r.expire(key, WINDOW_VELOCITY)

    def distinct_fail_ips(self, ts):
        return int(self.r.pfcount(self._bucket("hll_failip", ts, WINDOW_VELOCITY)))

    def add_user_ip(self, user, ip, ts):
        key = self._bucket("hll_userip", ts, WINDOW_CROSS, user)
        self.r.pfadd(key, ip)
        self.r.expire(key, WINDOW_CROSS)

    def distinct_ips_for_user(self, user, ts):
        return int(self.r.pfcount(self._bucket("hll_userip", ts, WINDOW_CROSS, user)))
