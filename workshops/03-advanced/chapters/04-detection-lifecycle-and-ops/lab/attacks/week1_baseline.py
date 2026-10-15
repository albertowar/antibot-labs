"""
Week 1: the adversaries this stack was built against

Two fleets from one operator, both out of datacenter ranges:

  naive       60 sessions. python-requests, no page JavaScript, a few addresses reused in bursts.
              The W1 stuffer. Every layer sees it.
  headless    40 sessions. Headless Chrome with navigator.webdriver left on, a SwiftShader GPU, a
              ruler for a mouse, pasted credentials. The W2 Ch1 bot, before stealth.

This is the traffic the week-1 baseline is measured on. Nothing here gets through, and that is the
point: the dashboard's "normal" is a winning stack. Next week it stops winning.

    python attacks/week1_baseline.py        play just these bots against the live store
"""

import random
import sys

from _common import (browser_headers, credential_list, fingerprint, ja4_for, play, pool_ip, report,
                     spread, straight_path)

SEED = 1101


def _naive(week, clock, creds, i):
    def run():
        headers = [("User-Agent", "python-requests/2.34.2"), ("Accept-Encoding", "gzip, deflate"),
                   ("Accept", "*/*"), ("Connection", "keep-alive")]
        return play("bot:naive", pool_ip("cloud_vm", 40 + i % 4), ja4_for("python-requests"), headers,
                    week, clock, creds, telemetry=False)
    return run


def _headless(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        fp = fingerprint(r, "chrome-win", "UTC",
                         renderer="ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)")
        fp["webdriver"] = True
        return play("bot:headless", pool_ip("hosting_asn", r.randrange(10)), ja4_for("chrome"),
                    browser_headers("chrome-win", week=1), week, clock, creds, fp, straight_path(r), [])
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    creds = credential_list(rng, 100, valid_share=0.05)
    out = []
    for i, clock in enumerate(spread(rng, week, 100)):
        out.append((clock, _naive(week, clock, creds[i], i) if i < 60
                    else _headless(week, clock, creds[i], rng)))
    return out


if __name__ == "__main__":
    report(sys.modules[__name__], 1)
