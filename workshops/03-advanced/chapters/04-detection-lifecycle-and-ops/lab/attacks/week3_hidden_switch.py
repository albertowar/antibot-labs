"""
Week 3: the switch you cannot see

Round 1 re-weighted the behaviour signals, and the impersonator's ruler
started costing it a block. The operator made two changes in the same week
the world moved:

  - residential exits: the fleet now connects from Example Broadband ranges
    (the resi-proxy pool shares the ISP's ASN with its customers), so
    datacenter_asn goes quiet on bots in the exact week it starts firing on
    real fiber customers whose ISP bought a cloud range (population.py).
  - a mouse with a hand: a Bezier path with jitter and uneven timing, as the
    W2 Ch3 humanizers produce. mouse_too_straight and timing_too_regular go
    quiet too.

150 sessions, a fresh address and fingerprint each. Per-request signals:
effectively none. The block rate falls and the false-positive rate spikes in
the same week, and the health report alone cannot say which half is the
adversary. That is what drift monitoring plus a data refresh is for, and what
labels are for after that.
"""

import random

from _common import (bot_session, browser_headers, credential_list, fingerprint, ip_from, ja4_for,
                     evader_path, outcome_of, spread, typed)

SEED = 1103


def _evader(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        s = bot_session("bot:evader", ip_from("resi-proxy", r.randrange(4000)), ja4_for("chrome"),
                        browser_headers("chrome-win", week=1), week, clock)   # fleet still on Chrome 145
        s.open_login()
        fp = fingerprint(r, "chrome-win", "America/New_York")
        s.send_telemetry(fp, evader_path(r), typed(r, len(creds[0]) + len(creds[1]), uniform=False), "mouse")
        return outcome_of(s.login(*creds)[0]), s
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    creds = credential_list(rng, 150, valid_share=0.05)
    return [(clock, _evader(week, clock, creds[i], rng))
            for i, clock in enumerate(spread(rng, week, 150))]
