"""
Week 2: the burned signals

The operator read a week of 403s and fixed the cheap things. Half the fleet is upgraded, half is
still the week-1 stuffer, because operators are lazy too:

  naive          50 sessions, unchanged. Still blocked.
  impersonator   100 sessions. A real Chrome's header set in Chrome's order and a Chrome JA4
                 (TLS-impersonation libraries do this for free), a stealth browser that hides
                 navigator.webdriver and reports a real GPU, credentials typed on a timer. Still out
                 of a cloud range, still a ruler for a mouse.

What the defender sees: http_library_ua, ja4_non_browser and header_order_mismatch stop firing on the
upgraded fleet. What the impersonator still shows: datacenter_asn (25), mouse_too_straight (15),
timing_too_regular (15) = 55, a proof-of-work the bot solves. The burned signals went quiet, nothing
errored, the block rate just fell. Round 1 is about noticing that in a day instead of a quarter.

    python attacks/week2_burned_signal.py   play just these bots against the live store
"""

import random
import sys

from _common import (browser_headers, credential_list, fingerprint, ja4_for, play, pool_ip, report, spread,
                     straight_path, typed)
from week1_baseline import _naive

SEED = 1102


def _impersonator(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        fp = fingerprint(r, "chrome-win", "America/New_York")
        return play("bot:impersonator", pool_ip("cloud_vm", 32 + r.randrange(28)), ja4_for("chrome"),
                    browser_headers("chrome-win", week=1), week, clock, creds, fp,
                    straight_path(r, jitter=0.3), typed(r, len(creds[0]) + len(creds[1])))
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    creds = credential_list(rng, 150, valid_share=0.05)
    out = []
    for i, clock in enumerate(spread(rng, week, 150)):
        out.append((clock, _naive(week, clock, creds[i], i) if i % 3 == 0
                    else _impersonator(week, clock, creds[i], rng)))
    return out


if __name__ == "__main__":
    report(sys.modules[__name__], 2)
