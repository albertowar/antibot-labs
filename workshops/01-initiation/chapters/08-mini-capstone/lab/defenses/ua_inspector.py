"""
W1 Ch3 module, reused unchanged by the capstone's `headers` layer: User-Agent Parsing

Parses the User-Agent with the open source `user-agents` library and scores
the obvious giveaways: library/CLI/headless markers, empty or truncated UA
strings, and browser versions that are too old (or on an OS they no longer
support) to be a real visitor.

In the capstone it runs inside defenses/headers.py from Round 1. Catches: wave 0
(default python-requests).

(Named ua_inspector, not ua_parser: a local ua_parser.py would shadow the
ua_parser package that user-agents imports.)
"""

import re

from user_agents import parse

# Oldest Chromium major we expect from real users. Bump this every quarter:
# Chrome auto-updates, so anything far behind stable is almost always forged.
MIN_CHROME_MAJOR = 140
MIN_FIREFOX_MAJOR = 115   # current Firefox ESR line

# Red flags in User-Agent strings
UA_RED_FLAGS = {
    "python-requests": "Raw HTTP library (Python requests)",
    "python-httpx": "Raw HTTP library (Python httpx)",
    "python-urllib": "Raw HTTP library (Python urllib)",
    "aiohttp": "Raw HTTP library (Python aiohttp)",
    "curl/": "CLI tool (curl)",
    "wget/": "CLI tool (wget)",
    "Go-http-client": "Go HTTP client",
    "Java/": "Java HTTP client",
    "okhttp": "OkHttp client",
    "node-fetch": "Node.js fetch library",
    "axios/": "Node.js axios library",
    "HeadlessChrome": "Headless Chrome (Selenium/Playwright default)",
    "PhantomJS": "PhantomJS headless browser",
    "Scrapy": "Scrapy web scraping framework",
    "libwww-perl": "Perl LWP library",
}


def parse_user_agent(ua_string):
    """
    Parse a User-Agent string and return structured information.

    Returns a dict with browser, OS, device info, and bot detection flags.
    """
    ua = parse(ua_string)
    return {
        "browser_family": ua.browser.family,
        "browser_major": ua.browser.version[0] if ua.browser.version else None,
        "browser_version": ".".join(str(v) for v in ua.browser.version if v is not None),
        "os_family": ua.os.family,
        "os_version": ".".join(str(v) for v in ua.os.version if v is not None),
        "device_family": ua.device.family,
        "is_mobile": ua.is_mobile,
        "is_pc": ua.is_pc,
        "is_bot": ua.is_bot,
    }


def check_ua_red_flags(ua_string):
    """Check a UA string against known red flag patterns."""
    flags = []
    for pattern, description in UA_RED_FLAGS.items():
        if pattern.lower() in ua_string.lower():
            flags.append({"pattern": pattern, "description": description})
    return flags


def score_user_agent(headers):
    """
    Layer 1: score the User-Agent header on its own.

    `headers` is any case-insensitive mapping (Flask's request.headers) or a
    plain dict. Returns (score, reasons).
    """
    ua_string = _get(headers, "User-Agent")
    score = 0
    reasons = []

    # 1. Missing User-Agent
    if not ua_string:
        return 50, ["Missing User-Agent header"]

    # 2. Known library / CLI / headless markers
    flags = check_ua_red_flags(ua_string)
    if flags:
        score += 40
        reasons.append(f"UA red flag: {flags[0]['description']}")

    info = parse_user_agent(ua_string)

    # 3. The library's own crawler list (Googlebot, bingbot, ...)
    if info["is_bot"] and not flags:
        score += 40
        reasons.append(f"UA self-identifies as a crawler ({info['browser_family']})")

    # 4. Truncated / hand-crafted ("Mozilla/5.0" and nothing else)
    if info["browser_family"] == "Other" and len(ua_string) < 40:
        score += 25
        reasons.append("UA is truncated or hand-crafted")

    # 5. Stale browser versions
    major = info["browser_major"]
    family = info["browser_family"]
    if major is not None:
        if family in ("Chrome", "Chromium", "Edge", "Chrome Mobile") and major < MIN_CHROME_MAJOR:
            score += 20
            reasons.append(f"{family} {major} is far behind stable (min {MIN_CHROME_MAJOR})")
        if family in ("Firefox", "Firefox Mobile") and major < MIN_FIREFOX_MAJOR:
            score += 20
            reasons.append(f"{family} {major} is far behind stable (min {MIN_FIREFOX_MAJOR})")

    # 6. Impossible OS / browser combination (Chrome 110+ dropped Windows 7/8)
    if re.search(r"Windows NT (5\.|6\.[0-3])", ua_string) and major and major >= 110 \
            and family.startswith("Chrome"):
        score += 20
        reasons.append(f"Chrome {major} cannot run on {info['os_family']} {info['os_version']}")

    return score, reasons


def _get(headers, name):
    """Case-insensitive header lookup that works for dicts and Flask headers."""
    value = headers.get(name)
    if value is None:
        for key, val in headers.items():
            if key.lower() == name.lower():
                return val
    return value or ""


if __name__ == '__main__':
    test_uas = [
        # Real browser
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
        # Python requests default
        "python-requests/2.32.5",
        # curl default
        "curl/8.5.0",
        # Headless Chrome
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36",
        # Very old browser on an OS it can't run on any more
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        # Truncated
        "Mozilla/5.0",
        # Empty
        "",
    ]

    for ua in test_uas:
        print(f"\nUA: {ua or '(empty)'}")
        if ua:
            info = parse_user_agent(ua)
            print(f"  Browser: {info['browser_family']} {info['browser_version']}")
            print(f"  OS: {info['os_family']} {info['os_version']}")
        score, reasons = score_user_agent({"User-Agent": ua})
        print(f"  Score: {score}")
        for r in reasons:
            print(f"  RED FLAG: {r}")
