"""
Shared machinery for the five weekly adversary profiles.

Each week's module exposes one function:

    sessions(week) -> [(clock, run)]      run() plays one adversary session and returns
                                          (outcome, result)

tools/weeks.py merges these with the customers by lab clock and replays the week; run on its own
(`python attacks/week2_burned_signal.py`) a module plays just its bots against the live store and
prints one JSON line. Outcome of a session: "reached" (signed in: a 200), "rejected" (a 401 from the
password check), "deceived" (a 401 that was really a block: the attacker cannot tell it from
"rejected", the store's verdict header can) or "refused" (a 403, or a step-up it cannot answer).

Restraint (AGENTS.md): each week's profile is exactly strong enough to get past the previous
round's defense, no stronger. These train defenders against your own local store; they are not
general-purpose tools. All safety rails live in tools/labclient.py (localhost only) and
data/world.json (documentation address ranges only); every session goes through them. The
credentials are synthetic: pairs generated from the lab's own seed. Most are wrong, some name
accounts that do not exist, and a small share are valid, which is the shape of a real
reused-password list. The adversary never reads a victim's inbox (owns_mailbox=False), so an
emailed step-up code is a wall.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import labclient  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402
from personas_ch4 import browser_headers, fingerprint, human_path, ja4_for  # noqa: E402
from signin import OpsClient, sign_in  # noqa: E402

N_USERS = 300
WEEK_SECONDS = 7 * 86400
__all__ = ["browser_headers", "fingerprint", "ja4_for", "pool_ip", "credential_list", "spread", "play",
           "straight_path", "evader_path", "human_timed_path", "typed", "report", "labclient"]


def pool_ip(pool, index):
    """The index-th address of a data/world.json pool (wraps around)."""
    hosts = labclient.world_pool(pool)
    return hosts[index % len(hosts)]


def credential_list(rng, n, valid_share, unknown_share=0.3, validated=None):
    """n (email, password) pairs for a reused-password list. `validated` restricts the valid slice
    to a set of account ids a checker already confirmed."""
    out = []
    for _ in range(n):
        r = rng.random()
        if r < valid_share:
            i = rng.choice(validated) if validated else rng.randrange(N_USERS)
            out.append((username(i), password_for(i)))
        elif r < valid_share + unknown_share:
            out.append((f"absent{rng.randrange(10_000):04d}@example.test", f"pw-{rng.randrange(10**6)}"))
        else:
            i = rng.randrange(N_USERS)
            out.append((username(i), f"{password_for(i)}x"))
    return out


def spread(rng, week, n, days=(1, 7)):
    """n lab clocks inside the given days of the week, sorted."""
    lo, hi = (days[0] - 1) * 86400, days[1] * 86400
    return sorted(week * WEEK_SECONDS + rng.randrange(lo, hi) for _ in range(n))


def play(actor, ip, ja4, headers, week, clock, creds, fp=None, mouse=(), keys=(), telemetry=True):
    """One bot session through the same sign-in a browser runs. Returns (outcome, result)."""
    client = OpsClient(actor, ip=ip, week=week, clock=clock, ja4=ja4)
    res = sign_in(client, headers, creds[0], creds[1], fp or {}, list(mouse), list(keys), "mouse",
                  owns_mailbox=False, telemetry=telemetry)
    verdict = (res.get("verdict") or ("",))[0]
    outcome = "reached" if res["status"] == 200 else "deceived" if verdict == "deceive" else \
        "refused" if res["status"] == 403 else "rejected"
    return outcome, res


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
    """A cheap 'humanizer': a curved path (so straightness stays well under the 0.98 rule) but a
    steady hand on the mouse timer. The inter-event jitter sits around 3 ms: above the 2 ms
    timing_too_regular line, so no rule fires, yet far tighter than a real hand's ~6 ms. No single
    signal flips; only a model that learned this band tells it from a person."""
    pts = human_path(rng)
    t = 0.0
    for p in pts:
        t += max(4.0, rng.gauss(9.0, 3.0))
        p[0] = round(t)
    return pts


def human_timed_path(rng):
    """The best evasion (week 5): a curved path with a real hand's timing jitter. Indistinguishable
    from a person in every feature the stack has, which is exactly why it is caught by the business
    metric, not a sensor."""
    return human_path(rng)


def typed(rng, count, uniform=True):
    t, keys = 400.0, []
    for _ in range(count):
        t += 90 if uniform else rng.uniform(80, 260)
        keys.append([round(t), round(t + (60 if uniform else rng.uniform(50, 140)))])
    return keys


def report(module, week, label=""):
    """Stand-alone mode: play this week's bots against the live store, print one JSON line."""
    labclient.wait_for_store()
    played = [run() for _, run in module.sessions(week)]
    reached = sum(1 for _, res in played if res["status"] == 200)
    print(json.dumps({"attack": module.__name__, "week": week, "attempted": len(played), "succeeded": reached,
                      "stopped": sum(1 for o, _ in played if o in ("deceived", "refused")), "note": label}))
