"""
Week 5: the novel profile that slips through (the W2 Ch9 hand-off)

Everything the stack learned through week 4 assumed the adversary reuses *something*: an address
pool, a fingerprint family, a behaviour helper with a tell. Week 5 is the profile W2 Ch9 ended on,
turned loose at scale:

  - a fresh fingerprint per session (new canvas, GPU, screen, timezone that matches the exit's
    region), so no fp_reuse and no fp_inconsistent
  - residential exits, one address per session, so no velocity and no datacenter_asn
  - a behaviour helper that curves the path *and* varies the timing enough to clear the re-weighted
    behaviour thresholds
  - credentials paced like a careful human: a trickle, spread across the week, so no campaign
    cluster goes hot

120 sessions. On week-5 signals the model scores it "clean" and the ruleset is quiet: it reaches the
password check and the valid pairs sign in. This is the attack you do not catch in real time. Round 4
is the incident response: notice it from the business metric (a failed-login and success-on-known-bad
pattern the sensors missed), contain with a TTL, label what you preserved, and turn it into the
training data and the new signal that the W3 capstone builds on. Week 6 replays the same farm while
the containment is in force.

    python attacks/week5_humanized_farm.py  play just these bots against the live store
"""

import random
import sys

from _common import (browser_headers, credential_list, fingerprint, human_timed_path, ja4_for, play, pool_ip,
                     report, spread, typed)

SEED = 1105
SCREENS = ["1920x1080", "1536x864", "2560x1440", "1440x900", "1366x768"]
TZS = ["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"]


def _ghost(week, clock, creds, rng):
    def run():
        r = random.Random(rng.random())
        fp = fingerprint(r, "chrome-win", r.choice(TZS))
        fp["screen"] = r.choice(SCREENS)
        fp["hardware_concurrency"] = r.choice([4, 8, 12, 16])
        return play("bot:humanized_farm", pool_ip("residential_proxy", r.randrange(400)), ja4_for("chrome"),
                    browser_headers("chrome-win", week=1), week, clock, creds, fp,
                    human_timed_path(r), typed(r, len(creds[0]) + len(creds[1]), uniform=False))
    return run


def sessions(week):
    rng = random.Random(SEED * week)
    creds = credential_list(rng, 120, valid_share=0.3, unknown_share=0.1)
    # Paced low and slow: a trickle across the whole week, never a burst.
    return [(clock, _ghost(week, clock, creds[i], rng))
            for i, clock in enumerate(spread(rng, week, 120))]


if __name__ == "__main__":
    report(sys.modules[__name__], 5)
