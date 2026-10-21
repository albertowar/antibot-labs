"""
Chapter 2, Round 1 defense (L1): User-Agent parsing.

Parses the User-Agent with the open source `user-agents` library and scores the obvious giveaways:
library, CLI and headless markers, empty or truncated strings, and browser versions too old (or on
an OS they no longer support) to be a real visitor.

What it catches: Round 1 (python-requests defaults), and every other client that does not bother
to change its User-Agent: curl, wget, Scrapy, a default headless Chrome.

What it misses: anything that sets a plausible string. The User-Agent is one line of attacker
code (Round 2), so this layer's job is to remove the laziest 60% of traffic cheaply, not to stop a bot.

Who it hurts: people on old browsers (the stale-version rule), and real API clients and monitoring
tools that use a library UA on purpose. Crawlers that identify themselves honestly (Googlebot) are
flagged here too: W4 Ch2 is about telling those apart from impostors by verifying them.

(Named ua_inspector, not ua_parser: a local ua_parser.py would shadow the ua_parser package that
user-agents imports.)

    python -m defenses.ua_inspector      # from the lab folder
"""

import re

from user_agents import parse

from . import policy
from .header_util import demo_ctx, note_reasons, show
from .pipeline import Check, Signal

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
    """Parse a User-Agent string into browser, OS, device and bot flags."""
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
    """Check a UA string against the known red-flag patterns."""
    return [{"pattern": p, "description": d} for p, d in UA_RED_FLAGS.items() if p.lower() in ua_string.lower()]


def score_user_agent(ua_string):
    """Score one User-Agent string on its own. Returns a list of Signals."""
    if not ua_string:
        return [Signal("ua", "missing", 50, "Missing User-Agent header")]
    signals = []

    flags = check_ua_red_flags(ua_string)
    if flags:
        signals.append(Signal("ua", "red_flag", 40, f"UA red flag: {flags[0]['description']}"))

    info = parse_user_agent(ua_string)
    if info["is_bot"] and not flags:                     # the library's own crawler list (Googlebot, bingbot, ...)
        signals.append(Signal("ua", "crawler", 40, f"UA self-identifies as a crawler ({info['browser_family']})"))
    if info["browser_family"] == "Other" and len(ua_string) < 40:     # "Mozilla/5.0" and nothing else
        signals.append(Signal("ua", "truncated", 25, "UA is truncated or hand-crafted"))

    major, family = info["browser_major"], info["browser_family"]
    if major is not None:
        floor = None
        if family in ("Chrome", "Chromium", "Edge", "Chrome Mobile"):
            floor = policy.MIN_CHROME_MAJOR
        elif family in ("Firefox", "Firefox Mobile"):
            floor = policy.MIN_FIREFOX_MAJOR
        if floor and major < floor:
            signals.append(Signal("ua", "stale_version", policy.STALE_VERSION_POINTS,
                                  f"{family} {major} is far behind stable (min {floor})"))
    # Chrome 110+ dropped Windows 7/8: an impossible combination
    if re.search(r"Windows NT (5\.|6\.[0-3])", ua_string) and major and major >= 110 and family.startswith("Chrome"):
        signals.append(Signal("ua", "impossible_os", 20, f"Chrome {major} cannot run on {info['os_family']} {info['os_version']}"))
    return signals


def _check(ctx):
    signals = score_user_agent(ctx.header("User-Agent", ""))
    note_reasons(ctx, signals)
    return signals


CHECK = Check("ua_inspector", _check, phases=("request",))


if __name__ == "__main__":
    samples = {
        "Real Chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
        "python-requests default": "python-requests/2.34.2",
        "curl default": "curl/8.5.0",
        "Headless Chrome": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36",
        "Old Chrome on an OS it cannot run on": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "Truncated": "Mozilla/5.0",
        "Empty": "",
    }
    for label, ua in samples.items():
        info = parse_user_agent(ua) if ua else None
        print(f"\nUA: {ua or '(empty)'}" + (f"\n  parsed as {info['browser_family']} {info['browser_version']} on {info['os_family']} {info['os_version']}" if info else ""))
        show(label, _check(demo_ctx({"User-Agent": ua})) if ua else score_user_agent(ua))
