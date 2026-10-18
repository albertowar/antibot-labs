"""
Round 2 attack: streaming evasion, a micro-burst and a low-and-slow poll (W3 Ch3). Level 6 stops them.

A session-level scorer meets a client once, at the action. That leaves a gap:

    burst   scrape the drop page in a tight burst: 45 requests in a couple of seconds. Each request on its own is
            fine; the pattern is not. A buy-time scorer sees one buy; the stream saw the burst.
    slow    poll the drop page every 350 ms to stay under every rate limit. The rate never trips, but the timing is
            machine-even: a human's gaps vary wildly, a script's do not.

The streaming layer (defenses/stream_*.py) scores the stream, so its counters have already moved by the time the next
request arrives: once the session is flagged, the rest of the burst meets a challenge instead of the page. The rate
detector catches the burst out of the box; the regularity detector only catches the slow poll once you set its CV
ceiling (the Round 2 TODO in defenses/stream_detectors.py).

    python attacks/round2_streaming.py [--pattern burst|slow]
"""

import argparse
import time

from _api import DROP, Bot, Cost, emit, rng_for, say, verdict


def _run(bot, n, interval_s):
    """GET the drop page n times. Returns the first refusal (or the last answer) and how many answers were the page."""
    served, first_refusal, last = 0, None, None
    for _ in range(n):
        last = bot.get(DROP)
        if last.status_code == 200:
            served += 1
        elif first_refusal is None:
            first_refusal = verdict(last)
        if interval_s:
            time.sleep(interval_s)
    view = bot.get("/lab/stream/me").json()
    detail = {"served": served, "of": n, "cv": view.get("cv"), "detectors": sorted(view.get("fired", {}))}
    if first_refusal is None:                                     # nothing refused it: the pattern evaded the stream
        return dict(verdict(last), status="reserved", **detail)
    return dict(first_refusal, **detail)


def burst(rng, n=45):
    return _run(Bot("bot:round2_burst", rng), n, 0)


def slow(rng, n=14, interval_s=0.35):
    return _run(Bot("bot:round2_slow", rng), n, interval_s)


PATTERNS = {"burst": burst, "slow": slow}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", choices=sorted(PATTERNS))
    args = ap.parse_args()
    names = [args.pattern] if args.pattern else sorted(PATTERNS)
    print(f"=== Round 2: {', '.join(names)} ===")
    results = []
    with Cost() as cost:
        for name in names:
            result = PATTERNS[name](rng_for(f"round2-{name}"))
            results.append(result)
            cv = f"cv={result['cv']:.3f}" if result.get("cv") is not None else ""
            say(name, result, f"{result['served']}/{result['of']} served {cv} {result['detectors']}")
    emit("round2_" + (args.pattern or "streaming"), results, cost,
         cv=[r.get("cv") for r in results], detectors=sorted({d for r in results for d in r["detectors"]}))
