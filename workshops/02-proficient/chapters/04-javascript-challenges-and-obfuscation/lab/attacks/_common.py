"""
Chapter 4: shared helpers for the attack scripts.

Every attack scrapes the same thing: the whole catalogue through the product API, the five
listing pages (/api/products?page=1..5, 24 products each) and then every product's record
(/api/products/<sku>, 120 of them, with its stock). That makes the numbers comparable across
rounds: records scraped, time taken, and how many challenge solves it took. All of it sits
behind the JavaScript gate (defenses/js_gate.py).

Rules of engagement, enforced in code: the store URL comes from tools/labclient.py, which asks
labnet.py at the lab root and refuses anything that is not this machine. Requests carry the lab
edge headers (a rented "residential" address from data/world.json and the bot's label), never
a real proxy. Browsers go through labclient.browser_context(), which aborts non-local requests.

Every attack ends by printing one JSON line for tools/checkpoint.py:
{"attempted": 125, "succeeded": <records that came back>, "solves": n, ...}
"""

import json
import os
import random
import re
import statistics
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, browser_context, world_pool  # noqa: E402,F401

LIST_PAGES = 5
PLANNED = LIST_PAGES + 120        # five listing pages + 120 product records

# What a scraper puts in User-Agent once it has been blocked for python-requests (W1 Ch4)
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")

# Server-Timing "gate" durations of requests that got through: what the defense costs the
# server on the happy path (a Redis lookup, plus an INCR at level 5).
GATE_MS = []


def bot_ip(rng=random):
    """A rented residential exit: this chapter's attacker already paid for clean IPs (W1 Ch3)."""
    return rng.choice(world_pool("residential_proxy_net"))


def lab_session(actor, ua=CHROME_UA, ip=None):
    """A requests.Session that speaks to the lab store as `bot:<actor>` from a rented address."""
    session = requests.Session()
    session.headers.update({"User-Agent": ua, "X-Lab-Client-IP": ip or bot_ip(), "X-Lab-Actor": f"bot:{actor}"})
    return session


def reason_of(r):
    try:
        body = r.json()
        err = body.get("error", {})
        return body.get("reason") or err.get("reason") or err.get("code") or f"HTTP {r.status_code}"
    except ValueError:
        return f"HTTP {r.status_code}"


def _get(session, path):
    r = session.get(f"{BASE_URL}{path}", timeout=10)
    m = re.search(r"gate;dur=([\d.]+)", r.headers.get("Server-Timing", ""))
    if r.status_code == 200 and m:
        GATE_MS.append(float(m.group(1)))
    return r


def scrape(session, state=None):
    """
    Fetch the catalogue until done or challenged. `state` ({"skus": [...], "done": n}) lets a
    caller resume after re-solving. Returns (records_ok, reason, seconds, state); reason is the
    store's 403 error, or None when everything came back.
    """
    state = state or {"skus": [], "done": 0}
    t0 = time.perf_counter()
    got = 0
    while state["done"] < PLANNED:
        i = state["done"]
        if i < LIST_PAGES:
            r = _get(session, f"/api/products?page={i + 1}")
            if r.status_code == 200:
                state["skus"] += [p["sku"] for p in r.json()["items"]]
        else:
            if i - LIST_PAGES >= len(state["skus"]):
                break
            r = _get(session, f"/api/products/{state['skus'][i - LIST_PAGES]}")
        if r.status_code != 200:
            return got, reason_of(r), time.perf_counter() - t0, state
        state["done"] += 1
        got += 1
    return got, None, time.perf_counter() - t0, state


def result(name, ok, reason, seconds, solves=0, solve_seconds=0.0):
    gate_ms = statistics.median(GATE_MS) if GATE_MS else None
    GATE_MS.clear()
    return {"attack": name, "attempted": PLANNED, "succeeded": ok, "reason": reason, "seconds": round(seconds, 2),
            "solves": solves, "solve_seconds": round(solve_seconds, 2),
            "gate_ms": round(gate_ms, 3) if gate_ms is not None else None}


def report(r):
    mark = "✅" if r["succeeded"] == r["attempted"] else "🛑"
    print(f"  {mark} scraped {r['succeeded']}/{r['attempted']} records in {r['seconds']:.2f} s")
    if r["solves"]:
        print(f"     challenge solves: {r['solves']} ({r['solve_seconds']:.2f} s solving)")
    if r["reason"]:
        print(f"     stopped: {r['reason']}")


def finish(r):
    """The last line every attack prints: one JSON object for tools/checkpoint.py."""
    print(json.dumps(r))
    return r


def challenge_payload(session, path="/api/products?page=1"):
    """What the gate hands a client that has not passed: the 403 JSON's payload (or None)."""
    r = session.get(f"{BASE_URL}{path}", timeout=10)
    if r.status_code != 403:
        return None
    try:
        return r.json()["error"].get("payload")
    except (ValueError, KeyError):
        return None


def verify(session, token, answer, solve_ms=0.1):
    r = session.post(f"{BASE_URL}/api/challenge/verify", timeout=10,
                     json={"type": "js", "answer": {"token": token, "answer": answer, "solve_ms": solve_ms}})
    return r.status_code == 200, (None if r.status_code == 200 else reason_of(r))
