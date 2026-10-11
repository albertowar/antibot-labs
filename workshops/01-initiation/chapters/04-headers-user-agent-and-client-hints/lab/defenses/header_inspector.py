"""
Chapter 4, Round 2 defense (L2): header presence and consistency.

User-Agent strings are trivial to fake. The rest of the header set has to tell the same story: real
browsers always send Accept, Accept-Language and Accept-Encoding, and every modern browser (Chrome 76+,
Firefox 90+, Safari 16.4+) sends Fetch Metadata (Sec-Fetch-*) whose values must make sense for the
request being made.

What it catches: Round 2 (a Chrome User-Agent on top of a library's default headers), and any client
that sends a Referer or Sec-Fetch-Site that contradicts itself.

What it misses: a client that copies a complete, self-consistent header set out of DevTools (Round 3).

Who it hurts: privacy tools and corporate proxies that strip Accept-Language or Referer; old browsers
that predate Fetch Metadata but claim a modern UA (rare); and anyone behind a proxy that rewrites
Accept-Encoding. Rules that look obvious can also be wrong: "Safari never sends Sec-Fetch-*" was true
until Safari 16.4 and would now block every Safari user. Check each rule against the browsers you
actually have.

    python -m defenses.header_inspector      # from the lab folder
"""

from urllib.parse import urlparse

from user_agents import parse

from .header_util import demo_ctx, lowered, note_reasons, show
from .pipeline import Check, Signal

# Real browsers send all of these on every request: name -> points when missing
EXPECTED_BROWSER_HEADERS = {"Accept": 20, "Accept-Language": 15, "Accept-Encoding": 10}
SEC_FETCH_HEADERS = ("Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest")

# First browser version that ships Fetch Metadata
SEC_FETCH_SINCE = {
    "Chrome": 76, "Chromium": 76, "Edge": 79, "Opera": 63, "Chrome Mobile": 76,
    "Firefox": 90, "Firefox Mobile": 90,
    "Safari": 16, "Mobile Safari": 16,
}


def claims_fetch_metadata_browser(ua_string):
    """(True, family) if the UA claims a browser version that always sends Sec-Fetch-*."""
    ua = parse(ua_string)
    since = SEC_FETCH_SINCE.get(ua.browser.family)
    major = ua.browser.version[0] if ua.browser.version else 0
    return since is not None and major >= since, ua.browser.family


def score_header_consistency(h, host=None):
    """Score a lower-cased header dict. `host` is the server's own host:port, to judge Sec-Fetch-Site/Referer."""
    signals = []
    ua_string = h.get("user-agent", "")

    for name, points in EXPECTED_BROWSER_HEADERS.items():                       # 1. presence
        if not h.get(name.lower()):
            signals.append(Signal("headers", f"missing_{name.lower().replace('-', '_')}", points, f"Missing {name} header"))

    is_browser, family = claims_fetch_metadata_browser(ua_string)                # 2. Fetch Metadata presence
    has_sec_fetch = any(name.lower() in h for name in SEC_FETCH_HEADERS)
    if is_browser and not has_sec_fetch:
        signals.append(Signal("headers", "no_sec_fetch", 25, f"UA claims {family} but Sec-Fetch-* headers are absent"))
    elif has_sec_fetch and not all(name.lower() in h for name in SEC_FETCH_HEADERS):
        signals.append(Signal("headers", "partial_sec_fetch", 10, "Partial Sec-Fetch-* set (browsers send Site, Mode and Dest together)"))

    mode = h.get("sec-fetch-mode", "")                                          # 3. Accept must match the request
    if h.get("accept", "").strip() == "*/*" and mode in ("", "navigate"):
        signals.append(Signal("headers", "accept_any_on_navigation", 10, "Accept is */* on a navigation (browsers send text/html,...)"))

    site, referer = h.get("sec-fetch-site", ""), h.get("referer", "")           # 4. Sec-Fetch-Site must agree with Referer
    if site in ("same-origin", "same-site") and not referer:
        signals.append(Signal("headers", "site_no_referer", 10, f"Sec-Fetch-Site={site} but no Referer"))
    if site == "same-origin" and referer and host and urlparse(referer).netloc != host:
        signals.append(Signal("headers", "referer_mismatch", 20,
                              f"Sec-Fetch-Site=same-origin but Referer is {urlparse(referer).netloc}"))
    if site == "none" and referer:
        signals.append(Signal("headers", "none_with_referer", 15, "Sec-Fetch-Site=none (typed URL/bookmark) yet a Referer is present"))
    return signals


def _check(ctx):
    signals = score_header_consistency(lowered(ctx), ctx.host)
    note_reasons(ctx, signals)
    return signals


CHECK = Check("header_inspector", _check, phases=("request",))


if __name__ == "__main__":
    chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    samples = {
        "python-requests defaults + Chrome UA": {
            "User-Agent": chrome_ua, "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive",
        },
        "Real Chrome navigation": {
            "User-Agent": chrome_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
        },
        "Copied capture replayed out of context": {
            "User-Agent": chrome_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://shop.example.com/",
            "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
        },
    }
    for label, headers in samples.items():
        show(label, score_header_consistency({k.lower(): v for k, v in headers.items()}, host="127.0.0.1:5000"))
