"""
W1 Ch4 module, reused unchanged by the capstone's `headers` layer: Header Presence & Consistency

User-Agent strings are trivial to fake. The rest of the header set has to
tell the same story: real browsers always send Accept, Accept-Language and
Accept-Encoding, and every modern browser (Chrome 76+, Firefox 90+,
Safari 16.4+) sends Fetch Metadata (Sec-Fetch-*) whose values must make
sense for the request being made.

In the capstone it runs inside defenses/headers.py from Round 1.
"""

from urllib.parse import urlparse

from user_agents import parse

# Real browsers send all of these on every request
EXPECTED_BROWSER_HEADERS = {
    "Accept": 20,
    "Accept-Language": 15,
    "Accept-Encoding": 10,
}

SEC_FETCH_HEADERS = ("Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest")

# First browser version that ships Fetch Metadata
SEC_FETCH_SINCE = {
    "Chrome": 76, "Chromium": 76, "Edge": 79, "Opera": 63, "Chrome Mobile": 76,
    "Firefox": 90, "Firefox Mobile": 90,
    "Safari": 16, "Mobile Safari": 16,
}


def claims_fetch_metadata_browser(ua_string):
    """True if the UA claims a browser version that always sends Sec-Fetch-*."""
    ua = parse(ua_string)
    since = SEC_FETCH_SINCE.get(ua.browser.family)
    major = ua.browser.version[0] if ua.browser.version else 0
    return since is not None and major >= since, ua.browser.family


def score_header_consistency(headers, host=None):
    """
    Layer 2: check that the header set looks like it came from a browser.

    `host` is the server's own host:port, used to judge whether
    Sec-Fetch-Site / Referer are contextually correct. Returns (score, reasons).
    """
    h = {k.lower(): v for k, v in headers.items()}
    ua_string = h.get("user-agent", "")
    score = 0
    reasons = []

    # 1. Presence: headers every browser sends
    for name, points in EXPECTED_BROWSER_HEADERS.items():
        if not h.get(name.lower()):
            score += points
            reasons.append(f"Missing {name} header")

    # 2. Fetch Metadata presence
    is_browser, family = claims_fetch_metadata_browser(ua_string)
    has_sec_fetch = any(name.lower() in h for name in SEC_FETCH_HEADERS)
    if is_browser and not has_sec_fetch:
        score += 25
        reasons.append(f"UA claims {family} but Sec-Fetch-* headers are absent")
    elif has_sec_fetch and not all(name.lower() in h for name in SEC_FETCH_HEADERS):
        score += 10
        reasons.append("Partial Sec-Fetch-* set (browsers send Site, Mode and Dest together)")

    # 3. Accept must match the kind of request
    mode = h.get("sec-fetch-mode", "")
    accept = h.get("accept", "").strip()
    if accept == "*/*" and mode in ("", "navigate"):
        score += 10
        reasons.append("Accept is */* on a navigation (browsers send text/html,...)")

    # 4. Contextual Sec-Fetch-Site: must agree with Referer
    site = h.get("sec-fetch-site", "")
    referer = h.get("referer", "")
    if site in ("same-origin", "same-site") and not referer:
        score += 10
        reasons.append(f"Sec-Fetch-Site={site} but no Referer")
    if site == "same-origin" and referer and host and urlparse(referer).netloc != host:
        score += 20
        reasons.append(f"Sec-Fetch-Site=same-origin but Referer is {urlparse(referer).netloc}")
    if site == "none" and referer:
        score += 15
        reasons.append("Sec-Fetch-Site=none (typed URL/bookmark) yet a Referer is present")

    return score, reasons


if __name__ == '__main__':
    chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    samples = {
        "python-requests defaults + Chrome UA": {
            "User-Agent": chrome_ua, "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*", "Connection": "keep-alive",
        },
        "Real Chrome navigation": {
            "User-Agent": chrome_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
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
        score, reasons = score_header_consistency(headers, host="localhost:5000")
        print(f"\n{label}: score={score}")
        for r in reasons:
            print(f"  - {r}")
