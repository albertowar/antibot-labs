"""
Chapter 3 shoppers: what a real Chromium does when the store sends Accept-CH.

The shoppers in tools/population.py are Python, not browsers, and `tools/browsers.py` gives them the
low-entropy headers a Chrome sends on its very first request. A real Chrome does one more thing: when a
response carries `Accept-CH`, it remembers the list for the origin and attaches those high-entropy hints
to every request that follows. At level 4 the store checks for exactly that, so without this module
every Chrome shopper would look like Round 4's bot and be blocked: a false positive that is the
simulator's fault, not the defense's. This module makes them behave like the browser they claim to be.

    PAGE_HOOKS: negotiate_hints   after a page load, if the response has Accept-CH, the persona's browser
                                  starts sending the hints (Chromium only: Firefox and Safari do not)
                                  and, if the response has Critical-CH, retries that navigation once,
                                  as Chromium does

It also wraps `browsers.headers_for` so a negotiated Chrome puts the three hints in Chrome's wire
order (arch before platform; platform version and full version list after it).

The simulator is intentionally generous: every Chrome shopper negotiates correctly. The real-world
failures (extensions that strip Sec-CH-*, cookie blockers) are in the discussion, not the lab.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL  # noqa: E402

NEGOTIATED = "ch"           # a 4th element on the persona's browser tuple once Accept-CH was honoured


def full_version(major):
    return f"{major}.0.{6000 + major * 10}.109"


def high_entropy(major, platform):
    """(arch, platform version, full version list) as Chromium sends them for that platform."""
    build = full_version(major)
    arch = '""' if platform == "android" else '"x86"'
    version = {"windows": '"15.0.0"', "macos": '"15.1.0"', "linux": '""', "android": '"14.0.0"'}[platform]
    brands = f'"Google Chrome";v="{build}", "Not?A_Brand";v="8.0.0.0", "Chromium";v="{build}"'
    return arch, version, brands


def _headers_for(original):
    def headers_for(browser, kind, base_url, referer=None):
        h = original(browser, kind, base_url, referer)
        if browser[0] != "chrome" or len(browser) < 4 or browser[3] != NEGOTIATED:
            return h
        arch, version, brands = high_entropy(browser[1], browser[2])
        out = []
        for name, value in h:
            if name.lower() == "sec-ch-ua-platform":
                out += [("sec-ch-ua-arch", arch), (name, value), ("sec-ch-ua-platform-version", version),
                        ("sec-ch-ua-full-version-list", brands)]
            else:
                out.append((name, value))
        return out
    headers_for._ch3 = True
    return headers_for


if not getattr(browsers.headers_for, "_ch3", False):
    browsers.headers_for = _headers_for(browsers.headers_for)


def negotiate_hints(p, client, r):
    """After each page load: honour Accept-CH like Chromium does (and Critical-CH: retry the navigation once)."""
    if p.browser[0] != "chrome" or not r.headers.get("Accept-CH") or (len(p.browser) > 3 and p.browser[3] == NEGOTIATED):
        return None
    p.browser = tuple(p.browser[:3]) + (NEGOTIATED,)
    p.result["accept_ch"] = r.headers["Accept-CH"]
    if r.headers.get("Critical-CH") and r.request.method == "GET":
        req = r.request.headers
        kind = "typed" if req.get("Sec-Fetch-Site") == "none" else "link"
        return client.get(r.request.path_url, browsers.headers_for(p.browser, kind, BASE_URL, req.get("Referer")),
                          allow_redirects=False)
    return None


if negotiate_hints not in population.PAGE_HOOKS:
    population.PAGE_HOOKS.append(negotiate_hints)


if __name__ == "__main__":
    for platform in ("windows", "macos", "linux", "android"):
        print(platform, high_entropy(153, platform))
