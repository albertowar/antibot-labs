"""
Layer: HTTP headers (stand-in for W1 Ch3)

User-Agent family, presence of the headers every modern browser sends on a
same-origin fetch, header order per browser family, and very old versions.

False positives: header order is rewritten by some corporate proxies and
security suites; very old browsers belong to people on old devices who
cannot upgrade. That is why order and age score low on their own.

W3 Ch4: the order corpus is *data with a date*. A browser release that
reorders headers turns this signal on for every one of its users until the
corpus is refreshed (corpus.py, tools/refresh_corpus.py). The corpus holds a
list of known orders per family, so a refresh adds the new order without
forgetting the old one that older installs still send.
"""

import re

import corpus

LAYER = "headers"
SIGNALS = {
    "http_library_ua": "User-Agent is an HTTP library, not a browser",
    "missing_browser_headers": "no Accept-Language or no Sec-Fetch-Site",
    "header_order_mismatch": "header order unlike the claimed browser",
    "outdated_browser": "browser major version far behind stable",
}

MIN_MAJOR = {"chrome": 140, "firefox": 115, "safari": 16}

# Relative order of the headers a page's fetch() sends, per engine (W1 Ch3).
# Only headers the client controls; Host, Cookie and Content-* are left out.
EXPECTED_ORDER = {
    "chrome": ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent", "accept",
               "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
               "accept-encoding", "accept-language"],
    "firefox": ["user-agent", "accept", "accept-language", "accept-encoding", "referer",
                "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
    "safari": ["accept", "sec-fetch-site", "accept-language", "sec-fetch-mode",
               "accept-encoding", "origin", "user-agent", "referer", "sec-fetch-dest"],
}

LIBRARIES = re.compile(r"python-requests|python-urllib|httpx|aiohttp|curl/|wget/|go-http-client"
                       r"|okhttp|java/|libwww|scrapy", re.I)


def parse_ua(ua):
    """Tiny UA parser: (family, major, os). Good enough for a lab, not for production."""
    if LIBRARIES.search(ua):
        return {"family": "library", "major": 0, "os": "unknown"}
    os_name = ("iOS" if re.search(r"iPhone|iPad", ua) else
               "Android" if "Android" in ua else
               "Windows" if "Windows" in ua else
               "macOS" if "Mac OS X" in ua else
               "Linux" if "Linux" in ua else "unknown")
    for family, pattern in (("firefox", r"Firefox/(\d+)"), ("chrome", r"(?:Chrome|CriOS)/(\d+)"),
                            ("safari", r"Version/(\d+).*Safari")):
        m = re.search(pattern, ua)
        if m:
            return {"family": family, "major": int(m.group(1)), "os": os_name}
    return {"family": "unknown", "major": 0, "os": os_name}


def known_orders(family):
    """The shipped order plus any the corpus refresh added."""
    return [EXPECTED_ORDER[family]] + corpus.updates().get("header_order", {}).get(family, [])


def _in_order(names, expected):
    seen = [n for n in names if n in expected]
    return seen == [n for n in expected if n in seen]


def sense(ctx):
    names = [name.lower() for name, _ in ctx.headers]
    ua = ctx.ua
    found = []
    if ua["family"] == "library":
        found.append("http_library_ua")
    if "accept-language" not in names or "sec-fetch-site" not in names:
        found.append("missing_browser_headers")
    if ua["family"] in EXPECTED_ORDER and not any(
            _in_order(names, order) for order in known_orders(ua["family"])):
        found.append("header_order_mismatch")
    if ua["family"] in MIN_MAJOR and ua["major"] < MIN_MAJOR[ua["family"]]:
        found.append("outdated_browser")
    return found
