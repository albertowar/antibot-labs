"""
L0 request checks: headers and per-egress rate (W1 Ch2, Ch4)

The cheapest layer, and still the one that removes most bulk traffic. It
runs on every request, before any session state is read.

    UA red flags             +60   HTTP libraries and HeadlessChrome name themselves
    Missing Accept-Language  +20   every mainstream browser sends it
    Browser UA, no Sec-Fetch +20   Chrome, Edge, Firefox and Safari 16.4+ all send Fetch Metadata
    > RATE_PER_MIN requests from one egress IP in a minute  +60
    > LOGINS_PER_10MIN login attempts from one egress IP     +60

Trade-off: the rate limits are deliberately loose. Office NAT, CGNAT and
university networks put hundreds of real users behind one IP; a tight
per-IP limit blocks them long before it slows a bot that rotates residential
proxies. Expect every agent in this chapter to walk straight past these limits: a user-directed
agent makes one purchase from one home IP.
"""

import re
import time

UA_RED_FLAGS = [
    (re.compile(r"python-requests|python-httpx|aiohttp|python-urllib", re.I), "Python HTTP library"),
    (re.compile(r"^curl/|libcurl|Go-http-client|okhttp|Java/|Wget", re.I), "Non-browser HTTP client"),
    (re.compile(r"HeadlessChrome", re.I), "Headless Chrome"),
    (re.compile(r"PhantomJS|Selenium|Puppeteer|Playwright", re.I), "Automation framework"),
]
BROWSER_UA = re.compile(r"Mozilla/5\.0 .*(Chrome/|Firefox/|Version/[\d.]+ (Mobile/\w+ )?Safari/)")
RATE_PER_MIN = 120
LOGINS_PER_10MIN = 20


def score_headers(ctx):
    headers, ua = ctx["headers"], ctx["ua"]
    points, reasons = 0, []
    if not ua:
        return 60, ["Empty User-Agent"]
    for pattern, label in UA_RED_FLAGS:
        if pattern.search(ua):
            points += 60
            reasons.append(f"UA red flag: {label}")
            break
    if BROWSER_UA.search(ua):
        if not headers.get("Accept-Language"):
            points += 20
            reasons.append("Browser UA but no Accept-Language")
        if not headers.get("Sec-Fetch-Mode"):
            points += 20
            reasons.append("Browser UA but no Sec-Fetch-* headers")
    return points, reasons


def score_rate(ctx, store, count=True):
    """Fixed-window counters per egress IP (W1 Ch2). count=False only reads them."""
    points, reasons = 0, []
    minute = int(time.time() // 60)
    key = f"rl:req:{ctx['egress']}:{minute}"
    n = int(store.incr(key)) if count else int(store.get(key) or 0)
    if count:
        store.expire(key, 120)
    if n > RATE_PER_MIN:
        points += 60
        reasons.append(f"{n} requests from {ctx['egress']} this minute (limit {RATE_PER_MIN})")
    if ctx["path"] == "/api/login" and ctx["method"] == "POST":
        bucket = int(time.time() // 600)
        key = f"rl:login:{ctx['egress']}:{bucket}"
        n = int(store.incr(key)) if count else int(store.get(key) or 0)
        if count:
            store.expire(key, 1200)
        if n > LOGINS_PER_10MIN:
            points += 60
            reasons.append(f"{n} login attempts from {ctx['egress']} in 10 min (limit {LOGINS_PER_10MIN})")
    return points, reasons


if __name__ == '__main__':
    ctx = {"headers": {"Accept": "*/*"}, "ua": "python-requests/2.34.2", "path": "/", "method": "GET"}
    print(score_headers(ctx))
    ctx["ua"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    print(score_headers(ctx))
