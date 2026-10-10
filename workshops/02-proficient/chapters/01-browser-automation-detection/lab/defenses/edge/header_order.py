"""
Workshop 1, Chapter 4 — Defense Layer 3b: Header Order Fingerprinting (Section 4.6)

Browsers emit headers in a fixed order baked into their network stack.
HTTP libraries use their own order (python-requests always starts with
User-Agent, Accept-Encoding, Accept, Connection), and copy-pasting header
*values* does not fix the *order*.

Rather than matching a full template (which changes between versions and
between navigation vs fetch requests), we check a few stable "A comes before
B" relationships that hold for Chromium.

Caveats: this only works when your server sees the raw order. Werkzeug's dev
server and gunicorn preserve it in the WSGI environ; many reverse proxies and
CDNs re-order or normalise headers. HTTP/2 lower-cases names, so casing is
not a signal here. Keep the weight low: alone it should only reach
"suspicious".

In W1 Ch4 this was enabled at DEFENSE_LEVEL >= 3. In W2 Ch1 it is always on (edge_rules.py).
"""

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
    """Return the list of (before, after) rules broken by this header order."""
    position = {}
    for i, name in enumerate(header_names):
        position.setdefault(name.lower(), i)
    broken = []
    for before, after in rules:
        if before in position and after in position and position[before] > position[after]:
            broken.append((before, after))
    return broken


def score_header_order(header_names, ua_string):
    """
    Layer 3b: compare header order with Chromium's. Only applied when the UA
    claims Chromium. Returns (score, reasons).
    """
    if "Chrome/" not in ua_string or "CriOS" in ua_string:
        return 0, []
    broken = order_violations(header_names)
    if len(broken) > MAX_VIOLATIONS:
        pairs = ", ".join(f"{a} before {b}" for a, b in broken)
        return 15, [f"Header order unlike Chromium ({len(broken)} rules broken: expected {pairs})"]
    return 0, []


if __name__ == '__main__':
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
        score, reasons = score_header_order(names, chrome_ua)
        print(f"\n{label}: score={score}")
        for r in reasons:
            print(f"  - {r}")
