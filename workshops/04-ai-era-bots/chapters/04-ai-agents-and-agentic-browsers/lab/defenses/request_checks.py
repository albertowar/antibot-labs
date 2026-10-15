"""L0 request checks: headers and a loose per-address rate (W1 Ch2, Ch4). Given; in SHADOW at every level.

The cheapest layer, and still the one that removes most bulk traffic. It runs on every request, before
any session state is read. Here it runs in shadow (`Check(shadow=True)`): it logs what it would have
said in `X-Lab-Shadow` and the decision log and never decides, because the starter's `smoke.py` and
plain HTTP tools talk to the store without a browser's headers. The point of keeping it in view is
what it says about the agents:

    UA red flags             +60   HTTP libraries and HeadlessChrome name themselves
    Missing Accept-Language  +20   every mainstream browser sends it
    Browser UA, no Sec-Fetch +20   Chrome, Edge, Firefox and Safari 16.4+ all send Fetch Metadata
    more than one burst of requests from one address (policy.RATE_LIMITS["agent_ip"])  rate_limit

Trade-off: the rate limit is deliberately loose. Office NAT, CGNAT and university networks put hundreds
of real users behind one address; a tight per-address limit blocks them long before it slows a bot that
rotates residential proxies. Every agent in this chapter walks straight past this layer: a
user-directed agent is a real Chromium, with real headers, making one purchase from one home address.
That is the point of Round 1.
"""

import re

from .pipeline import Check, Signal, Verdict

UA_RED_FLAGS = [
    (re.compile(r"python-requests|python-httpx|aiohttp|python-urllib", re.I), "Python HTTP library"),
    (re.compile(r"^curl/|libcurl|Go-http-client|okhttp|Java/|Wget", re.I), "Non-browser HTTP client"),
    (re.compile(r"HeadlessChrome", re.I), "Headless Chrome"),
    (re.compile(r"PhantomJS|Selenium|Puppeteer|Playwright", re.I), "Automation framework"),
]
BROWSER_UA = re.compile(r"Mozilla/5\.0 .*(Chrome/|Firefox/|Version/[\d.]+ (Mobile/\w+ )?Safari/)")


def score_headers(ctx):
    ua = ctx.ua.raw
    points, reasons = 0, []
    if not ua:
        return 60, ["Empty User-Agent"]
    for pattern, label in UA_RED_FLAGS:
        if pattern.search(ua):
            points += 60
            reasons.append(f"UA red flag: {label}")
            break
    if BROWSER_UA.search(ua):
        if not ctx.header("Accept-Language"):
            points += 20
            reasons.append("Browser UA but no Accept-Language")
        if not ctx.header("Sec-Fetch-Mode"):
            points += 20
            reasons.append("Browser UA but no Sec-Fetch-* headers")
    return points, reasons


def _check(ctx):
    if not ctx.bucket("agent_ip", ctx.ip):
        return Verdict("rate_limit", retry_after=5)
    points, reasons = score_headers(ctx)
    return [Signal("request_checks", "headers", points, "; ".join(reasons)[:140])] if points else None


CHECK = Check("request_checks", _check, phases=("request",), shadow=True)


if __name__ == '__main__':
    class _Ctx:
        class ua:
            raw = "python-requests/2.34.2"
        header = staticmethod(lambda name, default=None: None)
    print(score_headers(_Ctx))
