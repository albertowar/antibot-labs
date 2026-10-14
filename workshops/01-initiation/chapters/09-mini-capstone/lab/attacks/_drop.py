"""
What the five scalper bots share, so each script stays about its idea.

  SKU, PATH         the drop: the Drop Hoodie, bought with POST /drop/lab-hoodie-1
  library_headers   what python-requests sends by default (a bot that changed nothing)
  parse_form        the drop form's inputs, with the wrappers around them (a markup-aware bot's view)
  fill              the body a form filler posts
  bought            did the store say "order confirmed"? (a trapped bot sees this too: it BELIEVES)
  solve_interstitial  what a script does with the PoW interstitial (Chapter 7's protocol, in Python)
  Tally, finish     the per-bot count and the one JSON line tools/drop.py reads
  async_context     a Playwright context for the async API that keeps labclient.browser_context's guard

Importing labclient runs the labnet localhost guard.
"""

import json
import os
import re
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import browsers  # noqa: E402
import trapkit  # noqa: E402
from labclient import BASE_URL, WORLD, is_local  # noqa: E402,F401
from pow_client import solve_here  # noqa: E402

SKU = "lab-hoodie-1"
PATH = f"/drop/{SKU}"
CHROME_MAJOR = 153
PAYLOAD = re.compile(r'<script type="application/json" id="pow-payload">(.*?)</script>', re.S)


def library_headers():
    """python-requests with its defaults: the lazy bot (W1 Ch4, Round 1)."""
    return [("User-Agent", "python-requests/2.34.2"), ("Accept-Encoding", "gzip, deflate"), ("Accept", "*/*"),
            ("Connection", "keep-alive")]


def chrome(kind, referer=None):
    """Chrome's header set copied out of DevTools (W1 Ch4, Round 3)."""
    return browsers.chrome(CHROME_MAJOR, "windows", kind, BASE_URL, referer)


class _DropForm(trapkit.FormParser):
    """trapkit's form parser, pointed at the drop form (class "buy", no id)."""

    def handle_starttag(self, tag, attrs):
        if tag == "form" and "buy" in (dict(attrs).get("class") or "").split():
            self.depth = len(self.stack)
        super().handle_starttag(tag, attrs)


def parse_form(html):
    """The drop form's inputs: [{name, type, value, checked, _ancestors, ...}]."""
    parser = _DropForm("\0")
    parser.feed(html)
    return [f for f in parser.inputs if f.get("name")]


def fill(fields, email, junk=None):
    """
    The body a form filler posts: every field the HTML shows, keeping what is already set (csrf, the
    timing token), the first size, `email` for the email box. With `junk`, any other text box gets it:
    that is how off-the-shelf bots meet a honeypot.
    """
    data = {}
    for f in fields:
        name, kind = f["name"], f.get("type", "text")
        if kind == "radio":
            if name not in data or "checked" in f:
                data[name] = f.get("value", "")
        elif kind == "hidden" or f.get("value"):
            data[name] = f.get("value", "")
        elif kind == "email":
            data[name] = email
        elif junk is not None:
            data[name] = junk
        else:
            data[name] = ""
    return data


def bought(r):
    return r.status_code == 200 and 'data-testid="order-confirmed"' in r.text


def solve_interstitial(client, r, tally, hdrs):
    """
    The gate answered with the proof-of-work page (a 403 carrying the payload). Solve it the way
    pow.js does, in Python, and post the answer from the same client. Returns True if the store
    accepted it. `hdrs` are the browser-like headers to send (the pass is bound to IP + User-Agent).
    """
    m = PAYLOAD.search(r.text)
    if r.status_code != 403 or not m:
        return False
    challenge = json.loads(m.group(1))
    counter = solve_here(challenge, tally)
    v = client.post("/api/challenge/verify", json={"type": "pow", "answer": {"challenge": challenge, "counter": counter}},
                    headers=[(k, v) for k, v in hdrs if k.lower() != "content-type"] + [("Content-Type", "application/json")])
    return v.status_code == 200


class Tally:
    """What one bot did, and what it believes it got."""

    def __init__(self, name):
        self.name, self.attempted, self.believed = name, 0, 0
        self.requests, self.statuses = 0, Counter()
        self.cpu_s, self.solves, self.bits, self.hashes = 0.0, 0, [], 0   # solve_here() charges these
        self.extra = {}
        self.started = time.perf_counter()

    def count(self, client):
        self.requests += client.requests
        self.statuses.update(client.statuses)

    def result(self):
        return {"name": self.name, "attempted": self.attempted, "succeeded": self.believed, "believed": self.believed,
                "requests": self.requests, "statuses": dict(self.statuses), "solves": self.solves,
                "cpu_s": round(self.cpu_s, 2), "bits": sorted(set(self.bits)), "wall_s": round(time.perf_counter() - self.started, 1),
                **self.extra}


def finish(title, tally):
    """Print a human line, then the one JSON line the harness reads."""
    r = tally.result()
    print(f"=== {title} ===\n  believes it bought {r['believed']} of {r['attempted']} attempts in {r['requests']} requests "
          f"· statuses {r['statuses']}" + (f" · PoW {r['solves']} solves, {r['cpu_s']} CPU-s" if r["solves"] else ""))
    print(json.dumps(r))


# --- Browsers (async API) -------------------------------------------------------------------------------

UA_OVERRIDE = {
    "userAgent": browsers.chrome_ua(CHROME_MAJOR, "windows"),
    "acceptLanguage": "en-US,en;q=0.9",
    "platform": "Win32",
    "userAgentMetadata": {
        "brands": [{"brand": "Google Chrome", "version": str(CHROME_MAJOR)}, {"brand": "Not?A_Brand", "version": "8"},
                   {"brand": "Chromium", "version": str(CHROME_MAJOR)}],
        "fullVersionList": [{"brand": "Google Chrome", "version": f"{CHROME_MAJOR}.0.0.0"},
                            {"brand": "Not?A_Brand", "version": "8.0.0.0"},
                            {"brand": "Chromium", "version": f"{CHROME_MAJOR}.0.0.0"}],
        "platform": "Windows", "platformVersion": "19.0.0", "architecture": "x86",
        "model": "", "mobile": False, "bitness": "64", "wow64": False,
    },
}


def sync_page(browser, actor, ip):
    """A fresh context on a rented address with consistent Chrome headers (sync API, labclient's guard).

    Headless Chromium gives itself away in its headers (W1 Ch4, Round 5): the UA says HeadlessChrome and
    Accept-Language is missing. One CDP call fixes both where Chromium generates them."""
    from labclient import browser_context
    context = browser_context(browser, actor, ip=ip)
    page = context.new_page()
    context.new_cdp_session(page).send("Emulation.setUserAgentOverride", UA_OVERRIDE)
    return context, page


async def async_page(browser, actor, ip):
    """The same, for the async API. Keeps labclient.browser_context's guard: a request that leaves this machine is aborted."""
    context = await browser.new_context(extra_http_headers={"X-Lab-Client-IP": ip, "X-Lab-Actor": actor})

    async def _route(route):
        if is_local(route.request.url):
            await route.continue_()
        else:
            await route.abort()
    await context.route("**/*", _route)
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("Emulation.setUserAgentOverride", UA_OVERRIDE)
    return context, page
