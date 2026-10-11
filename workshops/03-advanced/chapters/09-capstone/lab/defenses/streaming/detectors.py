"""
Capstone L6 — the three streaming detectors (W3 Ch3)

Each detector is an online update over per-session state in Redis, so it costs
O(1) memory per session no matter how long the stream runs.

    rate        sliding-window request count (a sorted set of timestamps)
    regularity  coefficient of variation of inter-arrival gaps, via Welford's
                online algorithm — bots are suspiciously even; humans are not
    navigation  ratio of actions (buy/login/api) to page views — a client that
                acts without ever browsing is walking the funnel backwards

observe() is called once per request. Points land in stream:pts:<sid> and the
reasons in stream:why:<sid>, which defenses/streaming/aggregator.py reads back
into the risk engine (L6).
"""

import json
import math

# rate: more than this many requests in the window is inhuman
RATE_WINDOW_S = 10
RATE_MAX = 30
RATE_POINTS = 55

# regularity (Welford): low CV == machine-even timing.
REG_MIN_SAMPLES = 8
# --- TODO (Round 2): the regularity threshold -------------------------------
# A human's inter-request gaps vary a lot (they read, pause, get distracted),
# so their coefficient of variation (std/mean) is high. A scripted low-and-slow
# stuffer sleeps a near-constant interval, so its CV is tiny. Run
# attacks/round2_streaming.py and watch the "low_and_slow" session's CV in
# tools/signalhealth.py, then set the ceiling below it and above the humans.
# Reference solution: solutions/round2/detectors.py.
REG_MAX_CV = 0.0                  # TODO (Round 2): ~0.15
# ----------------------------------------------------------------------------
REG_POINTS = 55

# navigation: acting without browsing
NAV_MIN_ACTIONS = 5
NAV_POINTS = 40

PAGE_PREFIXES = ("/drop", "/login", "/register", "/account", "/")
ACTION_PATHS = ("/api/buy", "/api/login", "/api/register", "/graphql", "/api/v1")


def _is_action(path):
    return any(path.startswith(p) for p in ACTION_PATHS)


def _is_page(path, method):
    return method == "GET" and (path == "/" or path.startswith(("/drop", "/login", "/register", "/account")))


def observe(store, event):
    """Update all three detectors for one request event; return current (points, reasons)."""
    sid, ts_ms, path, method = event["sid"], event["ts_ms"], event["path"], event["method"]
    if not sid:
        return 0, []
    points, reasons = 0, []

    # --- rate: sliding window of request timestamps -------------------------
    rkey = f"stream:rate:{sid}"
    store.zadd(rkey, {f"{ts_ms}:{store.incr('stream:seq')}": ts_ms})
    store.zremrangebyscore(rkey, 0, ts_ms - RATE_WINDOW_S * 1000)
    store.expire(rkey, RATE_WINDOW_S * 4)
    n = store.zcard(rkey)
    if n > RATE_MAX:
        points += RATE_POINTS
        reasons.append(f"{n} requests in {RATE_WINDOW_S}s (> {RATE_MAX}): burst rate")

    # --- regularity: Welford online variance of inter-arrival gaps ----------
    wkey = f"stream:welf:{sid}"
    w = store.hgetall(wkey)
    last = float(w.get("last", 0) or 0)
    count = int(w.get("n", 0) or 0)
    mean = float(w.get("mean", 0) or 0)
    m2 = float(w.get("m2", 0) or 0)
    if last:
        gap = (ts_ms - last) / 1000.0
        count += 1
        delta = gap - mean
        mean += delta / count
        m2 += delta * (gap - mean)
    store.hset(wkey, mapping={"last": ts_ms, "n": count, "mean": mean, "m2": m2})
    store.expire(wkey, 1800)
    if count >= REG_MIN_SAMPLES and mean > 0:
        cv = math.sqrt(m2 / count) / mean
        if cv <= REG_MAX_CV:
            points += REG_POINTS
            reasons.append(f"inter-request CV {cv:.3f} <= {REG_MAX_CV} over {count} gaps: "
                           f"machine-even timing (low-and-slow)")

    # --- navigation: actions without page views -----------------------------
    nkey = f"stream:nav:{sid}"
    field = "action" if _is_action(path) else ("page" if _is_page(path, method) else "other")
    store.hincrby(nkey, field, 1)
    store.expire(nkey, 1800)
    nav = store.hgetall(nkey)
    actions, pages = int(nav.get("action", 0) or 0), int(nav.get("page", 0) or 0)
    if actions >= NAV_MIN_ACTIONS and pages == 0:
        points += NAV_POINTS
        reasons.append(f"{actions} actions, 0 page views: funnel skipped (API-only client)")

    prev = int(store.get(f"stream:pts:{sid}") or 0)
    points = max(points, prev)  # points are sticky for the session: a burst seen once still counts
    store.set(f"stream:pts:{sid}", points, ex=1800)
    if reasons:
        store.set(f"stream:why:{sid}", json.dumps(reasons), ex=1800)
    return points, reasons


def cv_for(store, sid):
    """The current coefficient of variation for a session (signalhealth.py uses this)."""
    w = store.hgetall(f"stream:welf:{sid}")
    count = int(w.get("n", 0) or 0)
    mean = float(w.get("mean", 0) or 0)
    m2 = float(w.get("m2", 0) or 0)
    if count < 2 or mean <= 0:
        return None
    return math.sqrt(m2 / count) / mean
