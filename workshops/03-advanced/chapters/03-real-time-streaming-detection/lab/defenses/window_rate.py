"""
Round 1 defense — sliding-window rate detector (on the stream)

The static rate limiter from W1 Ch1 counts requests in a *fixed* window: it
resets on the minute, so a burst that straddles the boundary is split in two
and may never cross the threshold. On a stream we keep a true *sliding*
window per (IP, endpoint): a sorted set scored by event time, trimmed to the
last WINDOW_RATE seconds on every event. The count is always "requests in the
last 60 seconds ending now", not "since the top of the minute".

This fires in milliseconds on the first event past the threshold, which is the
whole point versus a session-level or batch model that waits for the session to
end. It catches a single noisy IP. It does NOT catch a burst spread thin across
many IPs — that is Round 2.

False positives: a shared egress (corporate NAT, CGNAT, a VPN exit) looks like
one very busy IP. The per-endpoint thresholds below are set well above a human
rate, and login/checkout are much tighter than search, but a big NAT is the
classic way this detector hurts real users. Measure it.
"""

from features import WINDOW_RATE
from stream import PREFIX

# requests per WINDOW_RATE seconds, per source IP, before we score
THRESHOLDS = {
    "/api/login": 20,
    "/api/register": 10,
    "/api/checkout": 15,
    "/api/search": 90,
    "default": 150,
}


def threshold_for(path):
    for endpoint, thr in THRESHOLDS.items():
        if endpoint != "default" and path.startswith(endpoint):
            return thr
    return THRESHOLDS["default"]


def detect(event, feats, sketches, r):
    ts = float(event["ts"])
    ip, path = event["ip"], event["path"]
    key = f"{PREFIX}win:{ip}:{path}"

    # Add this request, drop everything older than the window, count what's left.
    r.zadd(key, {f"{event['sid']}:{ts}:{feats['n']}": ts})
    r.zremrangebyscore(key, 0, ts - WINDOW_RATE)
    r.expire(key, WINDOW_RATE)
    count = r.zcard(key)

    thr = threshold_for(path)
    soft = min(1.0, count / thr) if thr else 0.0
    if count > thr:
        return soft, {
            "sid": event["sid"], "ip": ip, "detector": "window_rate",
            "signal": "ip_burst", "count": count, "threshold": thr,
            "endpoint": path, "bot_score": round(min(1.0, (count - thr) / thr + 0.5), 3),
            "action": "block", "ts": ts,
        }
    return soft, None
