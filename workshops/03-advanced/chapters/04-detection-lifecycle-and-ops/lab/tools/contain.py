"""
Containment with a timer (Round 4)

When an attack is live and you do not yet understand it, you buy time by
trading false positives for false negatives: tighten the score, or turn on
the campaign step-up, knowing it will catch some real users too. The
discipline is that every such change has a deadline. contain.py writes the
change with an until_clock, and defenses/config.py drops it automatically
when the lab clock passes it, so the 02:00 mitigation does not quietly
become next quarter's policy.

    python tools/contain.py --lower-block 45 --for-weeks 1      block at 45 until a week passes
    python tools/contain.py --campaign-stepup --for-weeks 1     step up hot clusters for a week
    python tools/contain.py --show
    python tools/contain.py --lift                              undo now, before the timer

Containment is not a fix. It stops the bleeding while you preserve evidence
(tools/snapshot.py), label what happened (tools/label.py), and build the
real detection (train.py + gate.py). The scoreboard (ops.py) shows its cost:
the real users you challenged to buy that time.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

import config  # noqa: E402
from report import decisions, read_log  # noqa: E402

WEEK_SECONDS = 7 * 86400


def latest_clock():
    entries = decisions(read_log())
    return max((e.get("clock", 0) for e in entries), default=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--lower-block", type=int, metavar="POINTS")
    parser.add_argument("--lower-challenge", type=int, metavar="POINTS")
    parser.add_argument("--campaign-stepup", action="store_true")
    parser.add_argument("--step-up-asn", type=int, metavar="ASN",
                        help="step up every login from this ASN (blunt; hits real users)")
    parser.add_argument("--for-weeks", type=float, default=1.0)
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--lift", action="store_true")
    args = parser.parse_args()

    if args.lift:
        config.update(challenge_at=None, block_at=None, campaign=False, stepup_asn=None,
                      until_clock=None, note="containment lifted")
        print("containment lifted")
        return 0
    changes = {}
    if args.lower_block is not None:
        changes["block_at"] = args.lower_block
    if args.lower_challenge is not None:
        changes["challenge_at"] = args.lower_challenge
    if args.campaign_stepup:
        changes["campaign"] = True
    if args.step_up_asn:
        changes["stepup_asn"] = args.step_up_asn
    if changes:
        deadline = int(latest_clock() + args.for_weeks * WEEK_SECONDS)
        changes["until_clock"] = deadline
        changes["note"] = f"containment, expires at clock {deadline}"
        config.update(**changes)
        print(f"contained: {changes}")
        print(f"  expires automatically at lab clock {deadline} "
              f"(~{args.for_weeks:g} week(s) from the last request)")
    cfg = config.load()
    print(f"\n  block_at={cfg.get('block_at')}, challenge_at={cfg.get('challenge_at')}, "
          f"campaign={cfg.get('campaign')}, stepup_asn={cfg.get('stepup_asn')}, "
          f"until_clock={cfg.get('until_clock')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
