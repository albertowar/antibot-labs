"""
Shared machinery for the five weekly adversary profiles

Each week's module exposes one function:

    sessions(week) -> [(clock, run)]      run() plays one adversary session
                                          and returns (outcome, LabSession)

tools/weeks.py merges these with the customers by clock and replays the
week. Outcome, from the adversary's side: "through" (it reached the
password check: 200 or 401) or "blocked" (403, or a step-up it cannot
answer).

Restraint (AGENTS.md): each week's profile is exactly strong enough to get
past the previous round's defense, no stronger. These train defenders
against your own local store; they are not general-purpose tools.
All safety rails live in tools/labclient.py (localhost only, documentation
address ranges only, synthetic *@example.test credentials only) and every
session goes through it.

The credential list is synthetic: pairs generated from the lab's own seed.
Most are wrong, some name accounts that do not exist, and a small share are
valid, which is the shape of a real reused-password list. The adversary
never reads a victim's inbox (owns_mailbox=False), so an emailed step-up
code is a wall.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import labclient  # noqa: E402
from labclient import LabSession, browser_headers, fingerprint, ip_from, ja4_for  # noqa: E402

users = labclient.users
WEEK_SECONDS = 7 * 86400


def credential_list(rng, n, valid_share, unknown_share=0.3, validated=None):
    """n (username, password) pairs for a reused-password list. `validated`
    restricts the valid slice to a set of account ids a checker already
    confirmed."""
    out = []
    for _ in range(n):
        r = rng.random()
        if r < valid_share:
            i = rng.choice(validated) if validated else rng.randrange(users.N_USERS)
            out.append((users.username(i), users.password(i)))
        elif r < valid_share + unknown_share:
            out.append((f"absent{rng.randrange(10_000):04d}@example.test", f"pw-{rng.randrange(10**6)}"))
        else:
            i = rng.randrange(users.N_USERS)
            out.append((users.username(i), f"{users.password(i)}x"))
    return out


def spread(rng, week, n, days=(1, 7)):
    """n lab clocks inside the given days of the week, sorted."""
    lo, hi = (days[0] - 1) * 86400, days[1] * 86400
    return sorted(week * WEEK_SECONDS + rng.randrange(lo, hi) for _ in range(n))


def outcome_of(outcome):
    return "through" if outcome in ("ok", "invalid") else "blocked"


def bot_session(actor, ip, ja4, headers, week, clock):
    return LabSession(actor, ip, ja4, headers, week=week, clock=clock, owns_mailbox=False)


# Fabricated telemetry --------------------------------------------------------

def straight_path(rng, n=30, jitter=0.0, interval=8.0, interval_jitter=0.0):
    """A ruler: evenly spaced points on a line, timer-driven."""
    sx, sy = rng.uniform(100, 400), rng.uniform(100, 300)
    ex, ey = 640, 420
    t, pts = 0.0, []
    for i in range(n):
        u = i / (n - 1)
        t += interval + rng.uniform(-interval_jitter, interval_jitter)
        pts.append([round(t), round(sx + (ex - sx) * u + rng.gauss(0, jitter)),
                    round(sy + (ey - sy) * u + rng.gauss(0, jitter))])
    return pts


def evader_path(rng):
    """A cheap 'humanizer': a curved path (so straightness stays well under
    the 0.98 rule) but a steady hand on the mouse timer. The inter-event
    jitter sits around 3 ms: above the 2 ms timing_too_regular line, so no
    rule fires, yet far tighter than a real hand's ~6 ms. No single signal
    flips; only a model that learned this band tells it from a person."""
    pts = labclient.human_path(rng)
    t = 0.0
    for p in pts:
        t += max(4.0, rng.gauss(9.0, 3.0))
        p[0] = round(t)
    return pts


def human_timed_path(rng):
    """The best evasion (week 5): a curved path with a real hand's timing
    jitter. Indistinguishable from a person in every feature the stack has,
    which is exactly why it is caught by the business metric, not a sensor."""
    return labclient.human_path(rng)


def typed(rng, count, uniform=True):
    t, keys = 400.0, []
    for _ in range(count):
        t += 90 if uniform else rng.uniform(80, 260)
        keys.append([round(t), round(t + (60 if uniform else rng.uniform(50, 140)))])
    return keys
