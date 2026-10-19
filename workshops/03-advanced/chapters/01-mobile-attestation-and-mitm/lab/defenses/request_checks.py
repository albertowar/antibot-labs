"""
Level 0, the baseline: is this request shaped like the mobile app, and is it too fast? (W1 Ch2, Ch4)

The cheapest layer, and the one every request to /api/mobile/* meets before any attestation is read.
This lab adds it at its own Round 0 because the W3 starter ships with an empty baseline.

    Non-app client UA                         +80   python-requests, curl, okhttp-with-no-app, an interception proxy
    Missing X-App-Id                          +30   the genuine app always sends its package name
    X-App-Id but not the app's User-Agent     +30
    Library TLS fingerprint (claimed JA4)     +10   a soft tell: W2 Ch3's table says which stacks are libraries
    Token bucket empty (240 burst, 4 / s)     rate_limit   per source address, policy.RATE_LIMITS["mobile_ip"]

Trade-off: a reverse engineer who has watched one genuine request through a proxy copies the app's
User-Agent and X-App-Id exactly, so this layer waves a faithful replay straight through. That is the whole
reason the later layers exist. Its job is only to drop the lazy, un-reversed traffic cheaply.

The rate limit is loose on purpose. Carrier-grade NAT puts thousands of real phones behind one address
(the starter's `mobile_cgnat` pool is two addresses for eight shoppers), so a tight per-address limit hurts
real users long before it slows a farm that rotates addresses. Expect the Round 4 farm to walk past it.

The JA4 is *claimed* here (X-Lab-JA4): this lab has no TLS edge, so it is as forgeable as the User-Agent.
A measured JA4 needs the edge W2 Ch3 builds; a faithful replay with an impersonating TLS stack matches the
app's JA4 anyway, which is why the weight is 10 and not 40.
"""

import re

from . import ja4
from .mobile_core import APP_ID
from .pipeline import Check, Signal, Verdict

APP_UA = re.compile(r"LabRunner/\d+\.\d+")  # the genuine app's UA prefix
NON_APP_UA = [
    (re.compile(r"python-requests|python-httpx|aiohttp|python-urllib", re.I), "Python HTTP library"),
    (re.compile(r"^curl/|libcurl|Go-http-client|Wget|HTTPie", re.I), "Non-app HTTP client"),
    (re.compile(r"mitmproxy|BurpSuite", re.I), "Interception proxy UA"),
]


def _check(ctx):
    # Only gate the mobile API surface on app shape; the web store is open.
    if not ctx.path.startswith("/api/mobile/"):
        return None
    if not ctx.ua.raw:
        return [Signal("app_shape", "empty_ua", 80)]
    signals = []
    for pattern, label in NON_APP_UA:
        if pattern.search(ctx.ua.raw):
            signals.append(Signal("app_shape", "non_app_client", 80, label))
            break
    if ctx.header("X-App-Id") != APP_ID:
        signals.append(Signal("app_shape", "no_app_id", 30))
    elif not APP_UA.search(ctx.ua.raw):
        signals.append(Signal("app_shape", "ua_not_app", 30))
    label = ja4.library_label(ja4.fingerprint(ctx))
    if label:
        signals.append(Signal("app_shape", "library_tls", 10, label))
    if not ctx.bucket("mobile_ip", ctx.ip):
        return Verdict("rate_limit", retry_after=1, signals=tuple(signals))
    return signals


CHECK = Check("app_shape", _check, phases=("request",))
