"""
Round checkpoint for W3 Ch3 (Real-Time Streaming Detection). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attacker next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attacker against Round 2's detectors (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 (ladder.py), your file kept as .bak
    python tools/checkpoint.py --restore              # put your own file back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is PRE-WRITTEN: every detector ships complete and a round is a DEFENSE_LEVEL. Catching up
means running the round at its level, which is what this does; `--catch-up` also restores the
reference ladder.py. The store appends every request to a Redis Stream, a consumer thread scores
the stream with the detectors the ladder enables at the level, and the gate refuses what they flag.

    round  level  adds                                   attacker (login attempts served, of those sent)
    -----  -----  -------------------------------------  --------------------------------------------------
      0    0      nothing: the log fills, nobody reads   micro-burst: all of them
      1    1      sliding-window rate (per IP)           micro-burst: only the first ~20
      2    2      + Count-Min / HyperLogLog sketches     IP rotation: the first 3 tries of every session
      3    3      + regularity, + distinct IPs/account   low-and-slow: the first ~20 IPs per account
      4    4      + composite (campaign term)            jittered browsers: caught once the campaign shows

"Served" is the metric: a streaming verdict stops what comes after it, never what came before.
`served_before_first_block` and `first_block_after_s` are the detection latency; `caught` is how many
sessions met a refusal. Next to the attacker run the 40 shoppers (tools/personas_ch3.py): none may be
stopped. Defender cost is the gate time of the shoppers' own requests plus the consumer's backlog.
The consumer's backlog (lag) is not a pass/fail number; it is something to watch: tools/lag.py.
"""

import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch3  # noqa: E402,F401  (registers the ch3_shop scenario)
import checkpoint_core  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

GATE_MEDIAN_MAX_MS = 20.0           # median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis every check costs a network round trip
DRAIN_TIMEOUT_S = 60


def drain(timeout=DRAIN_TIMEOUT_S):
    """Wait until the consumer has no backlog, so every verdict of the round exists before we read it."""
    deadline = time.time() + timeout
    st = {}
    while time.time() < deadline:
        st = labclient.admin("GET", "/lab/stream/status")
        if st["backlog"] == 0:
            time.sleep(0.15)                       # the last batch may still be writing its flags
            return labclient.admin("GET", "/lab/stream/status")
        time.sleep(0.1)
    return st


def stream_state(board, results, attacks):
    """The stream's side of the round: the consumer kept up, and how late the flags were."""
    st = drain()
    rows = labclient.admin("GET", "/lab/stream/verdicts", params={"limit": 2000})["items"]
    lags = sorted(v["lag_ms"] for v in rows)
    detectors = sorted({v["detector"] for v in rows})
    print(f"\nthe stream: {st['events']} events · consumer {st['events_per_s']:.0f} events/s · backlog now {st['backlog']} "
          f"· {len(rows)} flags from {', '.join(detectors) or 'nothing'}")
    if lags:
        print(f"  a flag lands {statistics.median(lags):.0f} ms (median), {lags[min(len(lags) - 1, int(0.95 * len(lags)))]:.0f} ms (p95) after the event that tripped it")
    return (st["backlog"] == 0, f"the consumer still has a backlog of {st['backlog']} after {DRAIN_TIMEOUT_S} s")


def attacker(name, served, caught=None, before=None, first_block=None):
    """
    served (lo, hi): login attempts the store served. caught (lo, hi): sessions that met a refusal.
    before (lo, hi): attempts served before the first refusal. first_block (lo, hi): seconds to the first refusal.
    Prints the attacker's line and the detection latency next to what a session-end scorer would wait.
    """
    def check(board, results, attacks):
        a = attacks.get(name) or {}
        got = {"served": a.get("succeeded", -1), "caught": a.get("caught", -1),
               "before": a.get("served_before_first_block", -1), "first_block": a.get("first_block_after_s")}
        want = {"served": served, "caught": caught, "before": before, "first_block": first_block}
        print(f"\nthe attacker ({name})\n  served {got['served']}/{a.get('attempted')} attempts · {a.get('caught')}/{a.get('sessions')} sessions met a refusal")
        if got["first_block"] is not None:
            print(f"  first refusal {got['first_block']} s into a {a.get('duration_s')} s campaign, after {got['before']} attempts were served "
                  f"(a session-end scorer waits ~{a.get('duration_s')} s)")
        else:
            print(f"  never refused; a session-end scorer would wait ~{a.get('duration_s')} s")
        bad = []
        for k, rng in want.items():
            if rng is None:
                continue
            v = got[k]
            if v is None:
                v = -1 if rng[0] >= 0 else None
            if v is None or not rng[0] <= v <= rng[1]:
                bad.append(f"{name} {k}: got {got[k]}, expected {rng[0]}-{rng[1]}")
        return (not bad, "; ".join(bad))
    return check


def people(board, results, attacks):
    rows = personas_ch3.population.summarize(results)
    n_hurt = sum(r["hurt"] for r in rows)
    print(f"\nthe people: {len(results)} shoppers · hurt {n_hurt} · logged in {sum(r['ok'] for r in rows)}")
    return (n_hurt == 0, f"{n_hurt} shoppers were stopped")


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    emit = [d["extra"].get("emit_ms", 0) for d in rows]
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    print(f"defender cost (the shoppers' requests, while the attacker runs)\n  gate per request: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} requests"
          f" · XADD after the response: median {statistics.median(emit):.2f} ms")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


ATTACKS = {
    "microburst": "attacks/round1_microburst.py",
    "ip_rotation": "attacks/round2_ip_rotation.py",
    "low_and_slow": "attacks/round3_low_and_slow.py",
    "jittered": "attacks/round4_jittered_browser.py",
}


def make_round(level, description, attack, checks, **kw):
    return Round(level=level, description=description, scenario="ch3_shop", attacks={attack: ATTACKS[attack]},
                 solutions=("defenses/ladder.py",), extra_checks=[stream_state, *checks, people, gate_cost], **kw)


ROUNDS = {
    0: make_round(0, "nothing reads the stream: the burst is served in full", "microburst",
                  [attacker("microburst", served=(300, 300), caught=(0, 0))]),
    1: make_round(1, "sliding-window rate on the stream", "microburst",
                  [attacker("microburst", served=(15, 40), caught=(1, 1), first_block=(0.3, 2.0))]),
    2: make_round(2, "heavy hitters: sketches see the campaign no IP shows", "ip_rotation",
                  [attacker("ip_rotation", served=(110, 130), caught=(36, 40))]),
    3: make_round(3, "regularity and the distinct-IP-per-account join", "low_and_slow",
                  [attacker("low_and_slow", served=(100, 135), caught=(190, 240))]),
    4: make_round(4, "the composite verdict with a global campaign term", "jittered",
                  [attacker("jittered", served=(140, 185), caught=(45, 70))]),
}

_check_round = checkpoint_core.check_round


def check_round(*args, **kwargs):
    """Every round, judged or not (--level), ends with the consumer drained, so the next reset cannot race a late flag."""
    out = _check_round(*args, **kwargs)
    drain()
    return out


checkpoint_core.check_round = check_round

if __name__ == "__main__":
    main(ROUNDS)
