"""
Level 6 (Round 2): the three streaming detectors (W3 Ch3).

The browser layers score one action at a time, at the moment it happens. A streaming layer scores the *stream*: it
sees every request as it arrives and keeps per-session state (a sliding rate window, an online variance estimate,
a navigation tally). That is what closes the latency gap: a burst that a session-level scorer meets only at the buy
has already moved the streaming counters by the time the next request arrives.

Each detector is an online update over per-session state in Redis, so it costs O(1) memory per session no matter
how long the stream runs:

    rate        sliding-window request count (a sorted set of timestamps)
    regularity  coefficient of variation of the inter-arrival gaps, via Welford's online algorithm: bots are
                suspiciously even; humans are not
    navigation  actions (buy, login, API) without a single page view: a client walking the funnel backwards

observe() is called once per request (by demo_site/ext/stream9.py, in the web process or in the consumer of
defenses/stream_bus.py). A detector that fires writes its points and reason to lab:stream:sig:<sid>, where
defenses/stream_layer.py reads them back on the request path. Points are sticky for the session: a burst seen once
still counts. State lives under `lab:` so POST /lab/reset clears it between rounds.
"""

import json
import math

from . import policy

# --- TODO (Round 2): the regularity threshold -------------------------------------------------------
# A human's inter-request gaps vary a lot (they read, pause, get distracted), so their coefficient of
# variation (std / mean) is high. A scripted low-and-slow poller sleeps a near-constant interval, so its CV
# is tiny. Run `python attacks/round2_streaming.py` and read the poller's CV (`python tools/signalhealth.py`
# prints the CV of every session), then set the ceiling below it and above the humans'.
# The reference solution is in solutions/round2/defenses/stream_detectors.py.
REG_MAX_CV = 0.0                  # TODO (Round 2): 0.15
# ---------------------------------------------------------------------------------------------------

STATE_TTL_S = 1800
ACTION_PATHS = ("/api/buy", "/api/login", "/api/register", "/graphql")
ACTION_POSTS = ("/login", "/register", "/checkout")
NOT_PAGES = ("/api/", "/graphql", "/ws/", "/lab/")


def _is_action(path, method):
    return path in ACTION_PATHS or path.startswith("/api/v1/") or \
        (method == "POST" and (path in ACTION_POSTS or path.startswith("/drop/")))


def _is_page(path, method):
    return method == "GET" and not path.startswith(NOT_PAGES)


def _fire(redis, sid, detector, points, reason):
    redis.hset(f"lab:stream:sig:{sid}", detector, json.dumps({"points": points, "reason": reason}))
    redis.expire(f"lab:stream:sig:{sid}", STATE_TTL_S)


def observe(redis, event):
    """Update all three detectors for one request event {sid, ts_ms, path, method}. Returns the detectors that fired now."""
    sid, ts_ms, path, method = event["sid"], event["ts_ms"], event["path"], event["method"]
    if not sid:
        return []
    fired = []

    # --- rate: a sliding window of request timestamps ----------------------------------------------
    rkey = f"lab:stream:rate:{sid}"
    redis.zadd(rkey, {f"{ts_ms}:{redis.incr('lab:stream:seq')}": ts_ms})
    redis.zremrangebyscore(rkey, 0, ts_ms - policy.STREAM_RATE_WINDOW_S * 1000)
    redis.expire(rkey, policy.STREAM_RATE_WINDOW_S * 4)
    n = redis.zcard(rkey)
    if n > policy.STREAM_RATE_MAX:
        _fire(redis, sid, "rate", policy.STREAM_RATE_POINTS,
              f"{n} requests in {policy.STREAM_RATE_WINDOW_S}s (> {policy.STREAM_RATE_MAX}): burst rate")
        fired.append("rate")

    # --- regularity: Welford's online variance of the inter-arrival gaps -------------------------------
    wkey = f"lab:stream:welf:{sid}"
    w = redis.hgetall(wkey)
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
    redis.hset(wkey, mapping={"last": ts_ms, "n": count, "mean": mean, "m2": m2})
    redis.expire(wkey, STATE_TTL_S)
    if count >= policy.STREAM_REG_MIN_SAMPLES and mean > 0:
        cv = math.sqrt(m2 / count) / mean
        if cv <= REG_MAX_CV:
            _fire(redis, sid, "regularity", policy.STREAM_REG_POINTS,
                  f"inter-request CV {cv:.3f} <= {REG_MAX_CV} over {count} gaps: machine-even timing (low-and-slow)")
            fired.append("regularity")

    # --- navigation: actions without page views ------------------------------------------------------
    nkey = f"lab:stream:nav:{sid}"
    field = "action" if _is_action(path, method) else ("page" if _is_page(path, method) else "other")
    redis.hincrby(nkey, field, 1)
    redis.expire(nkey, STATE_TTL_S)
    nav = redis.hgetall(nkey)
    actions, pages = int(nav.get("action", 0) or 0), int(nav.get("page", 0) or 0)
    if actions >= policy.STREAM_NAV_MIN_ACTIONS and pages == 0:
        _fire(redis, sid, "navigation", policy.STREAM_NAV_POINTS,
              f"{actions} actions, 0 page views: funnel skipped (API-only client)")
        fired.append("navigation")
    return fired


def verdict(redis, sid):
    """What the request path reads: {detector: {points, reason}} for this session (one HGETALL)."""
    if not sid:
        return {}
    return {k: json.loads(v) for k, v in redis.hgetall(f"lab:stream:sig:{sid}").items()}


def cv_for(redis, sid):
    """The current coefficient of variation for a session (the lab routes and signalhealth.py show it)."""
    w = redis.hgetall(f"lab:stream:welf:{sid}")
    count = int(w.get("n", 0) or 0)
    mean = float(w.get("mean", 0) or 0)
    m2 = float(w.get("m2", 0) or 0)
    if count < 2 or mean <= 0:
        return None
    return math.sqrt(m2 / count) / mean


if __name__ == "__main__":
    import fakeredis
    r = fakeredis.FakeStrictRedis(decode_responses=True)
    t = 1_000_000
    for i in range(14):                                   # a poller: one request every 350 ms, almost no jitter
        observe(r, {"sid": "poller", "ts_ms": t + i * 350 + (i % 3), "path": "/drop/lab-runner-9", "method": "GET"})
    for i in range(14):                                   # a person: pauses of 0.4 to 6 s
        observe(r, {"sid": "person", "ts_ms": t + [0, 900, 2500, 3100, 9000, 9800, 14000, 15200, 21000, 21500,
                                                   26000, 30000, 31200, 38000][i],
                    "path": "/", "method": "GET"})
    for i in range(40):                                   # a burst
        observe(r, {"sid": "burst", "ts_ms": t + i * 40, "path": "/drop/lab-runner-9", "method": "GET"})
    print(f"starter REG_MAX_CV={REG_MAX_CV}: poller CV {cv_for(r, 'poller'):.3f}, person CV {cv_for(r, 'person'):.3f}")
    print("  poller fired:", sorted(verdict(r, "poller")), "| person fired:", sorted(verdict(r, "person")),
          "| burst fired:", sorted(verdict(r, "burst")))
    assert "rate" in verdict(r, "burst")
    REG_MAX_CV = 0.15
    r.flushall()
    for i in range(14):
        observe(r, {"sid": "poller", "ts_ms": t + i * 350 + (i % 3), "path": "/drop/lab-runner-9", "method": "GET"})
    assert "regularity" in verdict(r, "poller"), "the solution's threshold must catch the poller"
    print("stream_detectors self-test OK (the 0.15 ceiling catches the poller)")
