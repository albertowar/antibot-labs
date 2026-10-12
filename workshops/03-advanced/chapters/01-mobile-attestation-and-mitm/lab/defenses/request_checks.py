"""
W3 Ch1 — L0 request checks: client shape and per-egress rate (W1 Ch1, Ch3)

The cheapest layer. It runs on every request before any attestation is read.
For a mobile API the "shape" checks are different from a web page:

    Non-app client UA        +60   python-httpx, curl, okhttp-with-no-app, etc.
    Missing/!= X-App-Id      +30   the genuine app always sends its package name
    > RATE_PER_MIN requests from one egress IP in a minute   +60

Trade-off: a reverse engineer who has watched one genuine request through a
proxy will copy the app's User-Agent and X-App-Id exactly, so L0 waves the
faithful replay straight through. That is the whole reason the later layers
exist. L0's job is only to drop the lazy, un-reversed traffic cheaply.

The rate limit is deliberately loose: carrier-grade NAT puts thousands of real
phones behind one IP, so a tight per-IP limit hurts real users long before it
slows a farm that rotates egress. Expect the Round 4 farm to walk past it.
"""

import re
import time

from mobile_core import APP_ID

APP_UA = re.compile(r"LabRunner/\d+\.\d+")  # the genuine app's UA prefix
NON_APP_UA = [
    (re.compile(r"python-requests|python-httpx|aiohttp|python-urllib", re.I), "Python HTTP library"),
    (re.compile(r"^curl/|libcurl|Go-http-client|Wget|HTTPie", re.I), "Non-app HTTP client"),
    (re.compile(r"mitmproxy|BurpSuite", re.I), "Interception proxy UA"),
]
RATE_PER_MIN = 240


def score_headers(ctx):
    headers, ua = ctx["headers"], ctx["ua"]
    points, reasons = 0, []
    if not ua:
        return 60, ["Empty User-Agent"]
    # Only gate the mobile API surface on app shape; web pages are open.
    if ctx["path"].startswith("/api/mobile/"):
        for pattern, label in NON_APP_UA:
            if pattern.search(ua):
                points += 60
                reasons.append(f"Mobile API called by a non-app client: {label}")
                break
        if headers.get("X-App-Id") != APP_ID:
            points += 30
            reasons.append("Mobile API request without the app's X-App-Id")
        elif not APP_UA.search(ua):
            points += 30
            reasons.append("X-App-Id present but User-Agent is not the app's")
    return points, reasons


def score_rate(ctx, store, count=True):
    """Fixed-window counter per egress IP (W1 Ch1). count=False only reads it."""
    points, reasons = 0, []
    minute = int(time.time() // 60)
    key = f"rl:req:{ctx['egress']}:{minute}"
    n = int(store.incr(key)) if count else int(store.get(key) or 0)
    if count:
        store.expire(key, 120)
    if n > RATE_PER_MIN:
        points += 60
        reasons.append(f"{n} requests from {ctx['egress']} this minute (limit {RATE_PER_MIN})")
    return points, reasons


if __name__ == '__main__':
    base = {"path": "/api/mobile/buy", "egress": "198.51.100.5"}
    print(score_headers({**base, "headers": {}, "ua": "python-httpx/0.28.1"}))
    print(score_headers({**base, "headers": {"X-App-Id": APP_ID}, "ua": "LabRunner/3.2.0 (Android 14; Pixel 8) okhttp/4.12.0"}))
