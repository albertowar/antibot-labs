"""
Week 2: the burned signals

The operator read a week of 403s and fixed the cheap things. Half the fleet
is upgraded, half is still the week-1 stuffer, because operators are lazy too:

  naive          50 sessions, unchanged. Still blocked.
  impersonator   100 sessions. A real Chrome's header set in Chrome's order
                 and a Chrome JA4 (TLS-impersonation libraries do this for
                 free), a stealth browser that hides navigator.webdriver and
                 reports a real GPU, credentials typed on a timer. Still out
                 of Example Cloud, still a ruler for a mouse.

What the defender sees: http_library_ua, ja4_non_browser and
header_order_mismatch stop firing on the upgraded fleet. What the
impersonator still shows: datacenter_asn (25), mouse_too_straight (15),
timing_too_regular (15) = 55, a proof-of-work the bot solves. The burned
signals went quiet, nothing errored, the block rate just fell. Round 1 is
about noticing that in a day instead of a quarter.
"""

import random

from _common import (bot_session, browser_headers, credential_list, fingerprint, ip_from, ja4_for,
                     outcome_of, spread, straight_path, typed)
from week1_baseline import _naive

SEED = 1102


def _impersonator(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        s = bot_session("bot:impersonator", ip_from("cloud", 70 + r.randrange(20)), ja4_for("chrome"),
                        browser_headers("chrome-win", week=1), week, clock)
        s.open_login()
        fp = fingerprint(r, "chrome-win", "America/New_York")
        s.send_telemetry(fp, straight_path(r, jitter=0.3), typed(r, len(creds[0]) + len(creds[1])), "mouse")
        return outcome_of(s.login(*creds)[0]), s
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    creds = credential_list(rng, 150, valid_share=0.05)
    out = []
    for i, clock in enumerate(spread(rng, week, 150)):
        out.append((clock, _naive(week, clock, creds[i], i) if i % 3 == 0
                    else _impersonator(week, clock, creds[i], rng)))
    return out
