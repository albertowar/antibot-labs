"""
Steer the canary (Round 3)

A canary model acts for a slice of sessions and is logged for all of them.
The slice is chosen by a stable hash of the session id (defenses/model.py),
so one person never flips models mid-session. The size lives in
data/ops_config.json and hot-reloads.

    python tools/canary.py --show
    python tools/canary.py --pct 10        send 10% of sessions to the canary model
    python tools/canary.py --pct 50
    python tools/canary.py --off           0%: the kill switch for a bad canary

The staged plan the chapter uses: 10% -> 50% -> 100%, watching
tools/rollback_watcher.py between steps. Reaching 100% is not promotion;
run `tools/registry.py promote <version>` to make it prod and clear the
canary, so the acting model is unambiguous.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

import config  # noqa: E402
import registry  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--pct", type=int)
    parser.add_argument("--off", action="store_true")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args()
    if args.off:
        config.update(canary_pct=0)
        print("canary at 0%")
    elif args.pct is not None:
        config.update(canary_pct=max(0, min(100, args.pct)))
        print(f"canary at {args.pct}%")
    roles = registry.load()["roles"]
    print(f"\ncanary model: {roles.get('canary') or '(none)'}   prod: {roles.get('prod') or '(none)'}   "
          f"canary_pct: {config.load().get('canary_pct', 0)}")
    if roles.get("canary") and not config.load().get("canary_pct"):
        print("  (a canary model is set but 0% of traffic reaches it; raise --pct)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
