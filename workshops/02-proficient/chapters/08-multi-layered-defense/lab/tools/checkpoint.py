"""
Chapter 8: Round checkpoint

Run at the end of every round. It resets the server's counters and log,
sends the 200 simulated customers through the login, and then reads the
decision log to report what the round's decision engine cost real people:

  - customers blocked (at level 3+ they were told "Invalid credentials")
  - customers challenged (proof-of-work solved by their browser, or a code
    they had to fetch from their inbox)
  - which personas paid, and which signals they paid for
  - defender cost: pipeline p50/p95 per login, median proof-of-work solve

It passes when the numbers sit inside the band expected for that level.
Round 1 is *expected* to block real customers: that is its lesson.

Fell behind? Every defense is already written. Catching up means restarting
the demo site with the round's level:
    cd demo_site && DEFENSE_LEVEL=<round> python app.py

Run:
    python tools/checkpoint.py --round 2
"""

import argparse
import statistics
import sys
from collections import Counter, defaultdict

import population
from report import (CHALLENGES, flat_signals, humans, pct, percentiles, persona, read_log,
                    server_reset, server_status)

# Expected band per level: (max % blocked, max % challenged, min % blocked)
EXPECTED = {
    0: (0.0, 0.0, 0.0),     # shadow mode: nothing enforced
    1: (25.0, 0.0, 5.0),    # veto chain: real customers get blocked, and that is the point
    2: (1.0, 15.0, 0.0),    # score + ladder: friction instead of blocks
    3: (1.0, 15.0, 0.0),    # + correlation: the budget must not move
    4: (1.0, 15.0, 0.0),    # + campaign: same budget, step-up only when a cluster is hot
}


def run_population():
    sessions, outcomes = [], Counter()
    for person in population.make_people():
        outcome, session = population.visit(person)
        sessions.append(session)
        outcomes[outcome] += 1
    return sessions, outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 5))
    parser.add_argument("--keep-log", action="store_true", help="append to the log instead of resetting")
    args = parser.parse_args()

    try:
        status = server_status()
    except OSError:
        print("❌ Demo site not reachable. Is it running? (DEMO_URL defaults to http://localhost:5000)")
        return 1
    level = status["level"]
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}, store {status['store']}) ===\n")
    if level != args.round:
        print(f"❌ Expected DEFENSE_LEVEL={args.round}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={args.round} python app.py")
        return 1
    if not args.keep_log:
        server_reset()

    sessions, seen = run_population()
    people = humans(read_log())
    total = len(people)
    blocked = [e for e in people if e["action"] == "block"]
    challenged = [e for e in people if e["action"] in CHALLENGES]

    print(f"Real customers ({total} logins)")
    print(f"  blocked     {len(blocked):>4}  {pct(len(blocked), total)}"
          + ("   (shown as 'Invalid credentials')" if level >= 3 and blocked else ""))
    print(f"  challenged  {len(challenged):>4}  {pct(len(challenged), total)}"
          f"   pow {sum(e['action'] == 'pow' for e in people)}, step-up {sum(e['action'] == 'step_up' for e in people)}")
    print(f"  what they saw: " + ", ".join(f"{k} {v}" for k, v in sorted(seen.items())))

    hurt = defaultdict(lambda: Counter())
    for e in blocked + challenged:
        hurt[persona(e)][e["action"]] += 1
    if hurt:
        print("\n  Who paid")
        pop_size = Counter(persona(e) for e in people)
        for p, actions in sorted(hurt.items(), key=lambda kv: -sum(kv[1].values())):
            print(f"    {p:<22} {sum(actions.values()):>3}/{pop_size[p]:<3} " +
                  ", ".join(f"{a} {n}" for a, n in sorted(actions.items())))
        why = Counter(s for e in blocked + challenged for s in flat_signals(e))
        print("  Signals they paid for: " + ", ".join(f"{s} {n}" for s, n in why.most_common(6)))
    if level == 1 and blocked:
        layers = Counter(e["veto_layer"] for e in blocked)
        print("  Vetoed by: " + ", ".join(f"{l} {n}" for l, n in layers.most_common()))

    print("\nDefender cost")
    p50, p95 = percentiles([e["ms"] for e in people])
    print(f"  pipeline: median {p50:.2f} ms, p95 {p95:.2f} ms per login")
    pow_times = [s.pow_ms for s in sessions if s.pow_ms]
    if pow_times:
        print(f"  proof-of-work: median {statistics.median(pow_times):.0f} ms per challenged customer "
              f"(Python; a browser's WebCrypto is faster)")

    max_block, max_chal, min_block = EXPECTED[level]
    block_rate, chal_rate = 100 * len(blocked) / total, 100 * len(challenged) / total
    failures = []
    if block_rate > max_block:
        failures.append(f"blocked {block_rate:.1f}% of real customers, budget {max_block:.0f}%")
    if block_rate < min_block:
        failures.append(f"blocked only {block_rate:.1f}%; at this level the veto chain should hurt")
    if chal_rate > max_chal:
        failures.append(f"challenged {chal_rate:.1f}%, budget {max_chal:.0f}%")
    print()
    if failures:
        for f in failures:
            print(f"❌ {f}")
        print("   Compare with the expected-results table in README.md. Did you change a weight or a line?")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
