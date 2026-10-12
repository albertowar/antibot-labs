"""
W1 Ch9 — The attacker's browser setup for waves 3 and 4.

Headless Chromium gives itself away in its headers (W1 Ch4, Round 5): the
User-Agent says HeadlessChrome, the Client Hints brand list says
HeadlessChrome, and Accept-Language is missing. One CDP call fixes all
three, because it rewrites them where Chromium generates them:

    Emulation.setUserAgentOverride(userAgent, acceptLanguage, userAgentMetadata)

After this, every header the browser sends is internally consistent and
in Chromium's real order, because a real Chromium is sending it. Header
scoring has nothing left to find. What still differs from a person
(navigator.webdriver, CDP side effects, rendering, input events, TLS) is
invisible to an HTTP-level defense; that is Workshop 2.

Each context rents its own source IP from the lab world (X-Lab-Source-IP),
exactly like labnet.LabClient does for scripts.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from browsers import chrome_ua  # noqa: E402

MAJOR = 153

UA_OVERRIDE = {
    "userAgent": chrome_ua(MAJOR, "windows"),
    "acceptLanguage": "en-US,en;q=0.9",
    "platform": "Win32",
    "userAgentMetadata": {
        "brands": [{"brand": "Google Chrome", "version": str(MAJOR)},
                   {"brand": "Not?A_Brand", "version": "8"},
                   {"brand": "Chromium", "version": str(MAJOR)}],
        "fullVersionList": [{"brand": "Google Chrome", "version": f"{MAJOR}.0.0.0"},
                            {"brand": "Not?A_Brand", "version": "8.0.0.0"},
                            {"brand": "Chromium", "version": f"{MAJOR}.0.0.0"}],
        "platform": "Windows", "platformVersion": "19.0.0", "architecture": "x86",
        "model": "", "mobile": False, "bitness": "64", "wow64": False,
    },
}


async def new_page(browser, ip, actor):
    """A fresh context (own cookies) on its own source IP, with consistent Chrome headers."""
    context = await browser.new_context(extra_http_headers={"X-Lab-Source-IP": ip, "X-Lab-Actor": actor})
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("Emulation.setUserAgentOverride", UA_OVERRIDE)
    return context, page
