"""
W3 Ch3 — Streaming feature store (per-session state + global sketches)

A streaming detector cannot re-read the whole log for every event. It keeps a
small amount of state per key and updates it in O(1) as each event arrives.
This module holds the two kinds of state the detectors share, so there is one
update path and no train/serve skew:

  SessionFeatures  per-session rolling features in a Redis hash:
                   counts, a "bought" flag, and Welford's online variance of
                   inter-arrival gaps (so we get timing regularity in O(1)
                   memory, never storing the gaps themselves).

  Sketches         global, sublinear-memory aggregates that would be far too
                   expensive as exact sets at scale:
                   - Count-Min    failed-login velocity per endpoint
                   - HyperLogLog  distinct source IPs (globally, and per user)
                   - Top-K        the heaviest endpoints, for the report

Every sketch is keyed by a time *bucket* (ts // window) and given a TTL, so a
new window starts a fresh sketch. Rate uses a short window; the cross-key
distinct-IP view uses a long one, because low-and-slow campaigns only become
visible when you look back far enough. That "longer window" is exactly what
Workshop 2 handed to this chapter.
"""

import math

from stream import PREFIX

WINDOW_RATE = 60       # seconds — per-IP request rate
WINDOW_VELOCITY = 600  # seconds — endpoint failed-login velocity
WINDOW_CROSS = 3600    # seconds — distinct-IP fan-out per user (low-and-slow)

LOGIN_PATHS = ("/api/login",)
ASSET_MARKERS = ("/static/", "/assets/", ".js", ".css", ".png", ".woff", ".ico")


def is_login(path):
    return any(path.startswith(p) for p in LOGIN_PATHS)


def is_asset(path):
    p = path.lower()
    return any(m in p for m in ASSET_MARKERS)


class SessionFeatures:
    """Per-session rolling features, updated once per event."""

    def __init__(self, r):
        self.r = r

    def _key(self, sid):
        return f"{PREFIX}sess:{sid}"

    def update(self, event):
        """Fold one event into the session's state and return its features."""
        sid = event["sid"]
        ts = float(event["ts"])
        key = self._key(sid)
        h = self.r.hgetall(key)

        n = int(h.get("n", 0)) + 1
        n_fail = int(h.get("n_fail", 0))
        n_asset = int(h.get("n_asset", 0))
        bought = h.get("bought", "0") == "1"
        first_ts = float(h.get("first_ts", ts))
        last_ts = float(h["last_ts"]) if "last_ts" in h else None

        failed_login = is_login(event["path"]) and event.get("status") in ("401", "403")
        if failed_login:
            n_fail += 1
        if is_asset(event["path"]):
            n_asset += 1
        if event["path"] == "/api/checkout" and event.get("status") == "200":
            bought = True

        # Welford online variance of inter-arrival gaps (O(1) memory).
        w_n = int(h.get("w_n", 0))
        w_mean = float(h.get("w_mean", 0.0))
        w_m2 = float(h.get("w_m2", 0.0))
        if last_ts is not None:
            gap = ts - last_ts
            w_n += 1
            delta = gap - w_mean
            w_mean += delta / w_n
            w_m2 += delta * (gap - w_mean)

        self.r.hset(key, mapping={
            "n": n, "n_fail": n_fail, "n_asset": n_asset,
            "bought": "1" if bought else "0", "first_ts": first_ts, "last_ts": ts,
            "w_n": w_n, "w_mean": w_mean, "w_m2": w_m2,
            "ip": event["ip"], "user": event.get("user", ""),
        })
        self.r.expire(key, WINDOW_CROSS)

        cv = None
        if w_n >= 2 and w_mean > 0:
            variance = w_m2 / (w_n - 1)
            cv = math.sqrt(variance) / w_mean
        return {
            "sid": sid, "ip": event["ip"], "user": event.get("user", ""),
            "n": n, "n_fail": n_fail, "n_asset": n_asset, "bought": bought,
            "cv": cv, "w_n": w_n, "duration_s": ts - first_ts,
        }


class Sketches:
    """Global probabilistic aggregates in sublinear memory."""

    def __init__(self, r):
        self.r = r

    def _bucket(self, kind, ts, window, *parts):
        b = int(float(ts) // window)
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
        key = self._bucket("cms", ts, WINDOW_VELOCITY)
        try:
            return int(self.r.execute_command("CMS.QUERY", key, path)[0])
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
        key = self._bucket("topk", ts, WINDOW_VELOCITY)
        try:
            return sorted(set(self.r.execute_command("TOPK.LIST", key)))
        except Exception:
            return []

    # --- HyperLogLog: distinct source IPs failing login, globally and per user ---
    def add_fail_ip(self, ip, ts):
        key = self._bucket("hll_failip", ts, WINDOW_VELOCITY)
        self.r.pfadd(key, ip)
        self.r.expire(key, WINDOW_VELOCITY)

    def distinct_fail_ips(self, ts):
        key = self._bucket("hll_failip", ts, WINDOW_VELOCITY)
        return int(self.r.pfcount(key))

    def add_user_ip(self, user, ip, ts):
        key = self._bucket("hll_userip", ts, WINDOW_CROSS, user)
        self.r.pfadd(key, ip)
        self.r.expire(key, WINDOW_CROSS)

    def distinct_ips_for_user(self, user, ts):
        key = self._bucket("hll_userip", ts, WINDOW_CROSS, user)
        return int(self.r.pfcount(key))
