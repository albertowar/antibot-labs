"""
Chapter 5: score a saved trace offline, at every level (Rounds 0-5).

    python tools/score_trace.py tools/traces/alice.json
    python tools/score_trace.py tools/traces/*.json

Runs the same layers the server runs, without a server. Level 4 is skipped:
replay detection needs the server's memory of other sessions.
Use it to check your own traces after every rule change, and to compare a
bot's trace with yours.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defenses.behavior import score_offline   # noqa: E402


def main(paths):
    if not paths:
        raise SystemExit("usage: python tools/score_trace.py <trace.json> [...]")
    for path in paths:
        trace = json.load(open(path))
        print(f"=== {os.path.relpath(path)} ({trace.get('source', '?')}) ===")
        for level in (1, 2, 3, 5):
            score, reasons, verdict = score_offline(trace, level)
            mark = {"allow": "✅", "challenge": "🟡", "block": "❌"}[verdict]
            print(f"  L{level}: {mark} {verdict:<9} score={score}")
            for reason in reasons:
                print(f"        - {reason}")


if __name__ == "__main__":
    main(sys.argv[1:])
