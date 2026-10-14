"""
ipkit: the scraper every Chapter 3 attack shares. Only WHERE the traffic comes from changes.

The target is the catalog API: GET /api/products/p001 .. p120, each product once, eight at
a time, with a real browser's headers (Chapter 4 is where headers matter). A product counts
as scraped if the store answered 200 with a price.

    scrape(name, next_ip, xff=None, keep_cookies=True)
        next_ip(i)   the source address for request i (rent it from data/world.json)
        xff(i)       an X-Forwarded-For value to send with request i, or None
        keep_cookies one cookie jar for the whole run (a session the store can follow),
                     or a fresh jar per request (a new session every time)

Ends by printing one JSON line: {"name", "attempted", "succeeded", "stopped", "signals",
"ips_used", ...}. The `signals` tally comes from X-Lab-Signals, the lab's oracle: it tells the
attacker exactly what tripped, which is why production never sends it.

Nothing here leaves this machine: labclient (and labnet.py behind it) refuses any DEMO_URL
that is not local, and every "proxy" is an address the store pretends to see.
"""

import collections
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor

import browsers
from labclient import BASE_URL, LabClient

SKUS = [f"p{i:03d}" for i in range(1, 121)]
THREADS = 8
SEED = 1337


def rng(salt=0):
    return random.Random(SEED + salt)


def headers():
    return browsers.headers_for(("chrome", 153, "windows"), "typed", BASE_URL)


def scrape(name, next_ip, xff=None, keep_cookies=True, skus=SKUS, extra=None):
    lock = threading.Lock()
    stopped, signals, ips = collections.Counter(), collections.Counter(), set()
    got = set()
    shared = LabClient(f"bot:{name}")
    if keep_cookies:
        shared.get("/", headers(), ip=next_ip(-1))      # land once: one session for the whole run

    def one(i_sku):
        i, sku = i_sku
        ip = next_ip(i)
        client = shared if keep_cookies else LabClient(f"bot:{name}")
        hdrs = headers() + ([("X-Forwarded-For", xff(i))] if xff else [])
        r = client.get(f"/api/products/{sku}", hdrs, ip=ip)
        ok = r.status_code == 200 and "price_cents" in r.text
        with lock:
            ips.add(ip)
            for s in filter(None, r.headers.get("X-Lab-Signals", "").split(",")):
                signals[s] += 1
            if ok:
                got.add(sku)
            else:
                stopped[{403: "blocked", 429: "rate_limited"}.get(r.status_code, str(r.status_code))] += 1

    with ThreadPoolExecutor(THREADS) as ex:
        list(ex.map(one, enumerate(skus)))
    out = {"name": name, "attempted": len(skus), "succeeded": len(got), "stopped": dict(stopped),
           "signals": dict(signals.most_common(6)), "ips_used": len(ips)}
    out.update(extra or {})
    return out


def finish(out):
    print(f"{out['name']}: scraped {out['succeeded']}/{out['attempted']} from {out['ips_used']} addresses   "
          f"stopped {out['stopped'] or 'nothing'}   signals {out['signals'] or '-'}")
    print(json.dumps(out))
