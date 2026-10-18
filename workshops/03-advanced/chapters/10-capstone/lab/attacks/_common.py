"""
Shared helpers for the Chapter 9 scalper scripts (rules of engagement built in).

Every script imports this module, which imports tools/labclient.py, which runs the labnet localhost guard:
the store URL comes from `labnet.target("DEMO_URL", ...)` and anything that is not this machine is refused
before a request is sent. Browsers get the same guard (labclient.browser_context aborts every non-local
request). No script supports proxies: the "residential" source addresses are rented from data/world.json
(documentation ranges), never real; every account, email, address and credential is synthetic.

What the bots claim about their TLS stack. The store sits behind no real TLS edge: it reads the JA4 a client
CLAIMS in `X-Lab-JA4` (W2 Ch5 teaches the measured version). Each simulated client claims what its real
stack would put on the wire (defenses/known_fingerprints.json), so a bot that reproduces a browser's
ClientHello (curl_cffi, a real Chromium or Firefox) claims the browser's, and a Python library claims the
library's. A bot cannot gain anything by lying here that it could not gain with the real handshake.

Every bot buys the drop (/drop/lab-runner-9) and reports what the gate said, from the X-Lab-* headers the lab
store adds to every response:

    reserved    the gate let it through and the pair was its (200 order confirmed / 201 on the API)
    challenge   403, verdict "challenge" (the "proof" challenge: a script that cannot run JavaScript stops here)
    blocked     403, verdict "block"
    failed      the form came back (invalid size or email): the bot's bug, not a defense

The last line a script prints is one JSON object for tools/checkpoint.py: {"attempted": n, "succeeded": k, ...}.
"""

import json
import os
import random
import resource
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, LabClient, browser_context, world_pool  # noqa: E402,F401

DROP = "/drop/lab-runner-9"
SKU = "lab-runner-9"
SIZES = ["7", "8", "9", "10", "11", "12"]
# JA4 a+b + a placeholder c, as in defenses/known_fingerprints.json (part c is not keyed on anywhere).
CLAIM = {"python": "t13d1712h1_ab0a1bf427ad_882d495ac381",       # python-requests 2.34 on OpenSSL 3.5
         "chromium": "t13d1516h2_8daaf6152771_806a8c22fdea",     # Chrome/Chromium, and curl_cffi's chrome profiles
         "gecko": "t13d1517h2_8daaf6152771_a87ad97598a9"}        # Firefox 155+, and Camoufox
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn", "avery", "rowan"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright", "scott", "green"]
RESHIPPER_UNITS = ["Unit {n}", "Apt {n}", "#{n}", "Ste {n}", "Suite {n}"]


def sleep_ms(ms):
    time.sleep(max(0, ms) / 1000)


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")


def bot_ip(rng=random):
    """A rented 'residential' exit (W1 Ch3 taught why the attacker pays for these)."""
    return rng.choice(world_pool("residential_proxy_net"))


def farm_identity(rng):
    """A scalper's throwaway account: random name + digits, shipping to one reshipper."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    unit = rng.choice(RESHIPPER_UNITS).format(n=rng.randint(1, 400))
    return {"email": email, "password": f"Farm-{rng.getrandbits(32):08x}", "name": email.split("@")[0],
            "address": f"48 Harbor Freight Way, {unit}, Elizabeth NJ 07201", "size": rng.choice(SIZES)}


def browser_ctx(browser, actor, ja4, ip=None, **kw):
    """A Playwright-API context (Chromium, Firefox or Camoufox) with the lab headers, the claimed JA4 and the guard."""
    ip = ip or bot_ip()
    ctx = browser_context(browser, actor, ip=ip, **kw)
    ctx.set_extra_http_headers({"X-Lab-Client-IP": ip, "X-Lab-Actor": actor, "X-Lab-JA4": ja4})
    return ctx


def outcome(status, verdict, signals="", confirmed=True):
    if verdict == "challenge":
        word = "challenge"
    elif verdict == "block" or status in (403, 429):
        word = "blocked"
    elif status in (200, 201) and confirmed:
        word = "reserved"
    elif status == 410:
        word = "sold_out"
    else:
        word = "failed"
    return {"status": word, "http": status, "verdict": verdict, "signals": [s for s in (signals or "").split(",") if s]}


def from_response(r):
    """outcome() for a `requests`/curl_cffi response."""
    return outcome(r.status_code, r.headers.get("X-Lab-Verdict"), r.headers.get("X-Lab-Signals"),
                   confirmed=r.status_code == 201 or "order-confirmed" in (r.text or ""))


def submit(page, click):
    """Run `click()` (which submits the drop form), wait for the page the store answers with."""
    try:
        with page.expect_navigation(timeout=30000) as nav:
            click()
    except Exception as exc:                          # the form never went out: the bot's bug, not a defense
        print(f"  submit: no navigation ({type(exc).__name__})", file=sys.stderr)
        return outcome(0, None)
    r = nav.value
    return outcome(r.status, r.headers.get("x-lab-verdict"), r.headers.get("x-lab-signals"),
                   confirmed="order-confirmed" in page.content())


def report(name, result):
    mark = {"reserved": "🟢", "challenge": "🟡", "blocked": "🔴"}.get(result["status"], "?")
    print(f"  {mark} {name:<26} {result['status']:<9} {result.get('http')}  {' '.join(result['signals'])}")


class Cost:
    """Wall-clock and CPU seconds for this process and its (finished) children: the economics are the point."""

    def __enter__(self):
        self.wall, self.cpu = time.perf_counter(), self._cpu()
        return self

    def __exit__(self, *exc):
        self.wall_s = time.perf_counter() - self.wall
        self.cpu_s = self._cpu() - self.cpu
        return False

    @staticmethod
    def _cpu():
        s, c = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
        return s.ru_utime + s.ru_stime + c.ru_utime + c.ru_stime


def finish(name, results, cost=None, **extra):
    """The last line every attack prints: one JSON object for tools/checkpoint.py."""
    out = {"attack": name, "attempted": len(results),
           "succeeded": sum(r["status"] == "reserved" for r in results),
           "challenged": sum(r["status"] == "challenge" for r in results),
           "blocked": sum(r["status"] == "blocked" for r in results),
           "signals": sorted({s for r in results for s in r["signals"]})[:8]}
    if cost is not None:
        out.update(wall_s=round(cost.wall_s, 2), cpu_s=round(cost.cpu_s, 2),
                   wall_s_per_attempt=round(cost.wall_s / max(1, len(results)), 2))
    out.update(extra)
    print(json.dumps(out))
    return out


def open_drop(page):
    """Land on the home page (the sensor reports there), then open the drop the way a customer does."""
    page.goto(BASE_URL + "/")
    page.wait_for_timeout(400)
    return page.goto(BASE_URL + DROP)


def refused(response):
    """The outcome when the gate refused the drop PAGE itself (a request-phase check), else None."""
    if response is not None and response.status != 200:
        return outcome(response.status, response.headers.get("x-lab-verdict"), response.headers.get("x-lab-signals"))
    return None


FIELDS = ("name", "email", "size")
SELECTOR = {"name": "#name", "email": "#email", "size": "#size", "reserve": "#drop-buy"}
