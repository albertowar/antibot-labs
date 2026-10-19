"""
Change the live policy without a deploy (Round 1)

Writes operator overrides to data/ops_config.json, which the store re-reads on
the next request (defenses/config.py). Nothing here restarts the server.

    python tools/configure.py --show
    python tools/configure.py --weight header_order_mismatch=0      kill a burned signal
    python tools/configure.py --weight mouse_too_straight=25 --weight timing_too_regular=25
    python tools/configure.py --challenge-at 25 --block-at 55
    python tools/configure.py --campaign on
    python tools/configure.py --reset                               back to the shipped policy

Always answer the one question first: who does this change hurt? Replay last
week against it before you ship it:

    python tools/sweep.py --weight header_order_mismatch=0          (replays the log against it)

A weight of 0 is a kill switch. Raising a weight to cover for a burned signal
is borrowing against the false-positive budget; `sweep.py` and `ops.py` show
the bill.
"""

import argparse
import sys

import report as _lab  # noqa: F401,E402  (puts the lab root on sys.path)
from defenses import config  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--weight", action="append", default=[], metavar="SIGNAL=POINTS")
    parser.add_argument("--challenge-at", type=int)
    parser.add_argument("--block-at", type=int)
    parser.add_argument("--campaign", choices=["on", "off"])
    parser.add_argument("--note", default=None)
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()

    if args.reset:
        config.clear()
        print("operator overrides cleared; the shipped policy is live")
        return 0
    changes = {}
    if args.weight:
        changes["weights"] = {}
        for item in args.weight:
            name, value = item.split("=")
            changes["weights"][name] = int(value)
    if args.challenge_at is not None:
        changes["challenge_at"] = args.challenge_at
    if args.block_at is not None:
        changes["block_at"] = args.block_at
    if args.campaign:
        changes["campaign"] = args.campaign == "on"
    if args.note is not None:
        changes["note"] = args.note
    if changes:
        config.update(**changes)
        print("wrote:", ", ".join(f"{k}={v}" for k, v in changes.items()))
    cfg = config.load()
    print("\ncurrent overrides (data/ops_config.json):")
    for key in ("weights", "challenge_at", "block_at", "campaign", "until_clock", "canary_pct", "note"):
        if cfg.get(key):
            print(f"  {key}: {cfg[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
