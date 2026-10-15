"""
Shared attacker helpers for Chapter 3.

Every attack in this chapter is a credential-stuffing campaign told as a schedule: a list of
timed requests, each from a rented source address, executed in order against the local store.
Timing matters here (a streaming detector reacts to the rate and the shape of events as they
arrive), so `execute()` sends each step at its scheduled second, on one thread, which also makes
the counts repeatable.

An attack ends by printing ONE JSON line (the checkpoint's contract):

    attempted                   login attempts sent
    succeeded                   attempts the store served (it answered 401, not a refusal)
    sessions / caught           sessions in the campaign / sessions that met at least one refusal
    served_before_first_block   attempts served before the first refusal: the price of detection latency
    first_block_after_s         seconds from the campaign's start to the first refusal (None if never)
    duration_s                  how long the campaign ran: what a session-end (batch) scorer waits for

Rules of engagement are enforced by tools/labclient.py (it imports the labnet guard): the target
is this machine, and source addresses come from data/world.json, never invented.
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "..", "tools"), os.path.join(HERE, "..")]

from labclient import BASE_URL, LabClient, world_pool  # noqa: E402,F401
from demo_site.seed import username  # noqa: E402,F401

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
REFUSED = (403, 429)


def wrong_password(n):
    """A guess that is not in the seed's top-100 list and not any account's password."""
    return f"Winter2026-{n:04d}!"


def login(sec_t, key, ip, email, password):
    return (sec_t, key, ip, "POST", "/api/login", {"email": email, "password": password}, True)


def page(sec_t, key, ip, path):
    return (sec_t, key, ip, "GET", path, None, False)


def execute(plan, actor, ua):
    """
    Run a plan: [(t, session key, ip, method, path, json body or None, is_login)], t in seconds from now.
    Each session key gets its own client (own cookie jar), so it is its own session at the store.
    """
    clients, sess = {}, {}
    t0 = time.time()
    attempted = served = before = 0
    first_block, blocked_seen = None, False
    for t, key, ip, method, path, body, is_login in sorted(plan, key=lambda s: s[0]):
        wait = t0 + t - time.time()
        if wait > 0:
            time.sleep(wait)
        c = clients.get(key) or clients.setdefault(key, LabClient(actor, ip=ip))
        r = c.request(method, path, headers=[("User-Agent", ua), ("Accept", "application/json" if body else "text/html")],
                      json=body)
        refused = r.status_code in REFUSED
        s = sess.setdefault(key, {"refused": 0})
        if refused:
            s["refused"] += 1
            if first_block is None:
                first_block = time.time() - t0
        if is_login:
            attempted += 1
            served += 0 if refused else 1
            if first_block is None:
                before += 1
    return {
        "attempted": attempted, "succeeded": served, "sessions": len(sess),
        "caught": sum(1 for s in sess.values() if s["refused"]),
        "served_before_first_block": before,
        "first_block_after_s": round(first_block, 2) if first_block is not None else None,
        "duration_s": round(time.time() - t0, 1),
    }


def finish(summary):
    print(json.dumps(summary))
