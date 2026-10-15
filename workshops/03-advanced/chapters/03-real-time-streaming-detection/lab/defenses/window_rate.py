"""
Round 1 defense: sliding-window rate per (IP, endpoint), computed on the stream.

A fixed-window limiter resets on the clock, so a burst that straddles the boundary is split in
two and may never cross the threshold. On a stream we keep a true *sliding* window per (IP,
endpoint): a sorted set scored by event time, trimmed to the last WINDOW_RATE seconds on every
event. The count is always "requests in the window ending now".

It fires on the first event past the threshold, a second or so into the burst, which is the
point against a session-level or batch model that waits for the session to end. The price is
that the first THRESHOLD requests were already served: a streaming verdict stops the rest of a
burst, never the start of it.

It catches one noisy IP. It does NOT catch a burst spread thin across many IPs (Round 2).

Who it hurts: a shared egress (corporate NAT, carrier-grade NAT, a VPN exit) looks like one very
busy IP, and the flag blocks every customer behind it until it expires. The login and checkout
thresholds are far above a human rate, but a big NAT is the classic way this detector hurts real
users. The subject of the flag is the IP, so the gate half is keyed on the IP.
"""

from . import streamlog
from .features import WINDOW_RATE
from .pipeline import Check

# requests per WINDOW_RATE seconds, per source IP, before we flag
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


def detect(event, feats, sketches, softs, r):
    """Stream half. Returns (soft score in [0, 1], verdict or None)."""
    ts = float(event["ts"])
    ip, path = event["ip"], event["path"]
    key = f"{streamlog.PREFIX}win:{ip}:{path}"

    # Add this request, drop everything older than the window, count what is left.
    r.zadd(key, {f"{event['sid']}:{ts}:{feats['n']}": ts})
    r.zremrangebyscore(key, 0, ts - WINDOW_RATE)
    r.expire(key, WINDOW_RATE)
    count = r.zcard(key)

    thr = threshold_for(path)
    soft = min(1.0, count / thr) if thr else 0.0
    if count > thr:
        return soft, {
            "sid": event["sid"], "ip": ip, "detector": "window_rate", "signal": "ip_burst",
            "subject": ("ip", ip), "count": count, "threshold": thr, "endpoint": path,
            "bot_score": round(min(1.0, (count - thr) / thr + 0.75), 3), "action": "block", "ts": ts,
        }
    return soft, None


# Gate half: refuse requests from an IP the stream flagged.
CHECK = Check("window_rate", streamlog.enforcer("window_rate", ("ip",)))
