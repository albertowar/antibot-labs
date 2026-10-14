"""
Chapter 4, Round 3 defense (L3b): header order fingerprinting.

Browsers emit headers in a fixed order baked into their network stack. HTTP libraries use their own
(python-requests starts with User-Agent, Accept-Encoding, Accept, Connection), and copy-pasting header
*values* does not fix the *order*. `ctx.headers` is a list in arrival order, with the lab's own
`X-Lab-*` headers already removed, so this check sees what a production origin would.

Rather than matching a full template (which changes between versions and between navigation and
fetch requests), it checks a few stable "A comes before B" relationships that hold for Chromium.

What it catches: Round 3 (copied values, Python's order), and any client that builds its header dict
by hand.

What it misses: a client that sets the order too (Round 4), and anything that is a real Chromium.

Who it hurts: it only works if your server sees the raw order. Many reverse proxies and CDNs re-order
or normalise headers, and HTTP/2 lower-cases names (so casing is not a signal here). Put this behind
a proxy you have not tested and it fires on real users. That is why the weight is low: alone it only
reaches "suspicious".

    python -m defenses.header_order      # from the lab folder
"""

from .header_util import demo_ctx, note_reasons, show
from .pipeline import Check, Signal

# (before, after) pairs that hold for Chromium on navigation and fetch requests
CHROMIUM_ORDER_RULES = [
    ("connection", "user-agent"),
    ("user-agent", "accept-encoding"),
    ("accept", "accept-encoding"),
    ("sec-fetch-dest", "accept-encoding"),
    ("accept-encoding", "accept-language"),
]
MAX_VIOLATIONS = 1


def order_violations(header_names, rules=CHROMIUM_ORDER_RULES):
    """The (before, after) rules broken by this header order."""
    position = {}
    for i, name in enumerate(header_names):
        position.setdefault(name.lower(), i)
    return [(a, b) for a, b in rules if a in position and b in position and position[a] > position[b]]


def score_header_order(header_names, ua_string):
    """Compare the header order with Chromium's. Applies only when the UA claims Chromium."""
    if "Chrome/" not in ua_string or "CriOS" in ua_string:
        return []
    broken = order_violations(header_names)
    if len(broken) > MAX_VIOLATIONS:
        pairs = ", ".join(f"{a} before {b}" for a, b in broken)
        return [Signal("header_order", "unlike_chromium", 15, f"Header order unlike Chromium ({len(broken)} rules broken: expected {pairs})")]
    return []


def _check(ctx):
    signals = score_header_order(ctx.header_names, ctx.ua.raw)
    note_reasons(ctx, signals)
    return signals


CHECK = Check("header_order", _check, phases=("request",))


if __name__ == "__main__":
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0 Safari/537.36"
    orders = {
        "Real Chrome navigation": [
            "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
            "Accept-Encoding", "Accept-Language",
        ],
        "python-requests with copied headers": [
            "Host", "User-Agent", "Accept-Encoding", "Accept", "Connection",
            "Accept-Language", "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
        ],
    }
    for label, names in orders.items():
        show(label, score_header_order(names, chrome_ua))
