"""
W3 Ch3 — Round checkpoint (self-contained; no six-terminal setup)

Run at the end of every round to check you are where you should be and to
measure BOTH sides. Unlike a Kafka+Faust pipeline that needs a broker and a
worker per detector, this checkpoint runs the whole thing in one process:

  1. reset this lab's keys
  2. generate the round's attack and the 40 legitimate customers
  3. append every event to the Redis Stream in time order (XADD)
  4. drain the stream through the detectors enabled at this round's level
  5. score both sides and compare to the expected results

    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 4 --slow   # simulate a lagging consumer

Levels are cumulative: L1 window_rate, L2 +heavy_hitters, L3 +regularity
+cross_key, L4 +composite. Round 0 runs at L0 (no streaming detector) to show
the gap the rest of the chapter closes.
"""

import argparse
import importlib
import sys

import lab  # noqa: F401  (sets sys.path)
import legit_traffic
import scoreboard
import store
import stream
import consumer

# round -> (level, attack module, expected result)
ROUNDS = {
    0: (0, "round0_recon", {"actor": "bot:microburst", "expect_zero": True}),
    1: (1, "round1_microburst", {"actor": "bot:microburst", "min_flag": 0.95}),
    2: (2, "round2_ip_rotation", {"actor": "bot:ip_rotation", "min_flag": 0.95}),
    3: (3, "round3_low_and_slow", {"actor": "bot:low_and_slow", "min_flag": 0.60}),
    4: (4, "round4_jittered_browser", {"actor": "bot:jittered", "min_flag": 0.60}),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 5))
    parser.add_argument("--slow", action="store_true",
                        help="add 1ms per event to simulate a consumer behind the stream")
    args = parser.parse_args()

    level, attack_name, expected = ROUNDS[args.round]
    r = store.connect()
    stream.reset(r)

    attack = importlib.import_module(attack_name)
    events = legit_traffic.generate() + attack.generate()
    events.sort(key=lambda e: float(e["ts"]))
    for e in events:
        stream.emit(r, e)

    print(f"=== Checkpoint: Round {args.round} (DEFENSE_LEVEL={level}, "
          f"{len(events)} events) ===\n")
    verdicts, stats = consumer.run(r, level, delay_per_event=0.001 if args.slow else 0.0)
    if args.slow:
        stats["note"] = "⚠️  --slow: a lagging consumer delays every verdict (see tools/lag.py)"

    failures = scoreboard.report(events, verdicts, stats, expected)
    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Compare with the Expected results table in README.md.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
