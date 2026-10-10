"""
W3 Ch3 — Scoreboard: both sides of every round

A detection rate on its own is half a result. Every checkpoint prints:

  Bot traffic     bot sessions flagged (challenge or block) — higher is better
  Real users      human sessions flagged — this is the cost, lower is better
  Detection speed streaming time-to-verdict vs. the batch baseline (session end)
  Defender cost   events processed per second, and the consumer's backlog (lag)

Ground truth — who is a bot — comes from each event's `actor` field, written by
the simulators. This module is the one place in the lab allowed to read it.
"""

import statistics

FLAGGED = ("challenge", "block")


def _median(xs):
    return statistics.median(xs) if xs else None


def ground_truth(events):
    """sid -> ('bot'|'human', actor_label), and sid -> (first_ts, last_ts)."""
    kind, span = {}, {}
    for e in events:
        sid, actor, ts = e["sid"], e["actor"], float(e["ts"])
        kind[sid] = ("bot" if actor.startswith("bot:") else "human", actor)
        lo, hi = span.get(sid, (ts, ts))
        span[sid] = (min(lo, ts), max(hi, ts))
    return kind, span


def report(events, verdicts, stats, expected):
    """Print the scoreboard. Returns the number of expectations that failed."""
    kind, span = ground_truth(events)
    bot_sids = {s for s, (k, _a) in kind.items() if k == "bot"}
    human_sids = {s for s, (k, _a) in kind.items() if k == "human"}

    def flagged(sids):
        return {s for s in sids if s in verdicts and verdicts[s]["action"] in FLAGGED}

    bots_flagged = flagged(bot_sids)
    humans_flagged = flagged(human_sids)
    failures = 0

    actor = expected["actor"]
    bot_n = len(bot_sids)
    bot_ok = len(bots_flagged)
    frac = bot_ok / bot_n if bot_n else 0.0
    print("Bot traffic                         sessions flagged")
    if expected.get("expect_zero"):
        good = bot_ok == 0
        failures += not good
        print(f"  {'✅' if good else '❌'} {actor:<28} {bot_ok}/{bot_n} flagged "
              f"(expected: none — no streaming detector at L0)")
    else:
        good = frac >= expected["min_flag"]
        failures += not good
        print(f"  {'✅' if good else '❌'} {actor:<28} {bot_ok}/{bot_n} ({frac:.0%}) "
              f"(expected: ≥ {expected['min_flag']:.0%})")

    print("\nReal users (40 simulated customers) flagged")
    hb = len(humans_flagged)
    good = hb == 0
    failures += not good
    print(f"  {'✅' if good else '❌'} {hb}/{len(human_sids)} flagged   (budget: 0)")
    for s in sorted(humans_flagged):
        v = verdicts[s]
        print(f"       {s}: {v['action']} by {v['detector']} ({v.get('signal')})")

    print("\nDetection speed")
    ttd = _median(stats.get("time_to_detect_s", []))
    batch = _median([hi - lo for s, (lo, hi) in span.items() if s in bot_sids])
    if ttd is not None:
        print(f"  streaming: first verdict a median {ttd:.2f}s into the session")
        if batch is not None:
            print(f"  batch:     a session-end scorer waits ~{batch:.1f}s (session length)")
    else:
        print("  streaming: no verdicts (nothing flagged)")
        if batch is not None:
            print(f"  batch:     a session-end scorer waits ~{batch:.1f}s (session length)")

    print("\nDefender cost")
    print(f"  consumer: {stats['events']} events at {stats['events_per_s']:.0f} events/s; "
          f"backlog pending={stats['pending']} lag={stats['lag']}")
    if stats.get("note"):
        print(f"  {stats['note']}")
    return failures
