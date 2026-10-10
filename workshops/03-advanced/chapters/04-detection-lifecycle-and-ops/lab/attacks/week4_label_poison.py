"""
Week 4: how the feedback loop gets poisoned

By week 4 the evader from week 3 reaches the password check on most
sessions, so for the valid pairs it found earlier it now signs in
successfully. That success is the problem the defender did not see coming.

The weak-label rule (defenses/labels.py) says: signed in with a valid
password and was not blocked, so label it human. Every evader session that
completes a login teaches next week's model that evader traffic is human.
The adversary is not just getting in; it is relabelling itself as a
customer for every retrain that follows.

The fleet is the week-3 evader, 160 sessions, residential exits, humanized,
a somewhat higher valid share because the earlier runs narrowed the list.
Nothing about one request looks worse than last week. What changed is the
*labels*, and a model retrained on weak labels alone (Round 3's first,
naive retrain) comes out worse than the one it replaces. The lesson is the
gate and the analyst-labelled holdout that catches it.
"""

import random

from _common import (bot_session, browser_headers, credential_list, fingerprint, ip_from, ja4_for,
                     evader_path, outcome_of, spread, typed)

SEED = 1104


def _returning(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        s = bot_session("bot:evader", ip_from("resi-proxy", r.randrange(4000)), ja4_for("chrome"),
                        browser_headers("chrome-win", week=1), week, clock)
        s.open_login()
        fp = fingerprint(r, "chrome-win", "America/New_York")
        s.send_telemetry(fp, evader_path(r), typed(r, len(creds[0]) + len(creds[1]), uniform=False), "mouse")
        return outcome_of(s.login(*creds)[0]), s
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    # A higher valid share: earlier runs confirmed these pairs work here.
    creds = credential_list(rng, 160, valid_share=0.25, unknown_share=0.15)
    return [(clock, _returning(week, clock, creds[i], rng))
            for i, clock in enumerate(spread(rng, week, 160))]
