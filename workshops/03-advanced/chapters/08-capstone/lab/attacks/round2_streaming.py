"""
Capstone Round 2 Attack — streaming evasion: micro-burst + low-and-slow (W3 Ch3)

A session-level scorer meets a client once, at the action. That leaves a gap:

    micro-burst   scrape inventory with a tight burst of requests. Each request
                  on its own is fine; the *pattern* — 40 in a few seconds — is
                  not. A buy-time scorer sees one buy; the stream saw the burst.
    low-and-slow  poll at a near-constant slow interval to stay under every rate
                  limit. The rate never trips, but the timing is machine-even:
                  a human's inter-request gaps vary wildly, a script's do not.

The streaming layer (defenses/streaming) scores the *stream*, so it has already
moved its counters by the time the next action arrives. This attack runs each
pattern in its own session and reads the session's streaming verdict back from
/whoami. The rate detector catches the burst out of the box; the regularity
detector only catches low-and-slow once you set its CV threshold (the Round 2
TODO in defenses/streaming/detectors.py).

Run (store running at DEFENSE_LEVEL 6):
    python attacks/round2_streaming.py
"""

import os
import sys
import time

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import Cost, egress_pool, report, rng_for, summary, target  # noqa: E402


def _session(egress):
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    return s


def _verdict(s, base):
    who = s.get(f"{base}/whoami").json()
    return who.get("stream", {}), who.get("sid")


def micro_burst(base, egress, n=45):
    """A tight burst of catalog requests: trips the sliding-window rate detector."""
    s = _session(egress)
    for i in range(n):
        s.get(f"{base}/drop/lab-runner-9")
    stream, sid = _verdict(s, base)
    evaded = stream.get("points", 0) == 0
    return {"pattern": "micro_burst", "evaded": evaded, "bought": evaded,
            "outcome": "allow" if evaded else "block",
            "reasons": stream.get("reasons", []), "sid": sid}


def low_and_slow(base, egress, n=14, interval_s=0.35):
    """Poll at a near-constant slow interval: under the rate limit, but machine-even."""
    s = _session(egress)
    for i in range(n):
        s.get(f"{base}/drop/lab-runner-9")
        time.sleep(interval_s)   # the tell: almost no jitter
    stream, sid = _verdict(s, base)
    evaded = stream.get("points", 0) == 0
    return {"pattern": "low_and_slow", "evaded": evaded, "bought": evaded,
            "outcome": "allow" if evaded else "block",
            "reasons": stream.get("reasons", []), "sid": sid,
            "cv": stream.get("cv")}


def run(verbose=False):
    base = target()
    rng = rng_for("round2")
    pool = egress_pool()
    with Cost() as cost:
        results = [micro_burst(base, rng.choice(pool)), low_and_slow(base, rng.choice(pool))]
    s = summary("round2_streaming", results, cost, success_key="evaded")
    if verbose:
        report(s, success_label="patterns evaded the stream")
        for r in results:
            extra = f" cv={r.get('cv')}" if r.get("cv") is not None else ""
            print(f"  {r['pattern']:<14} {r['outcome']:<6}{extra} {r['reasons'][:2]}")
    return s


if __name__ == '__main__':
    run(verbose=True)
