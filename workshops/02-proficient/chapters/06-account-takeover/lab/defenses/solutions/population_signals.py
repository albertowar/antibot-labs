"""L2 reference: per-cohort failure and unknown-account ratios.

A distributed stuffer rotates IPs so no single address looks busy, but the whole
run still shares *something*: a rented /24, an ASN, a client signature. Group
attempts by that cohort and two ratios give the game away:

  * failure ratio — stuffing tests mostly-wrong passwords, so failures dominate.
  * unknown-account ratio — combo lists are full of emails that were never your
    users, so most attempts name accounts that do not exist.

Either ratio, once a cohort has enough attempts to be worth judging (MIN_SAMPLE),
latches a challenge on the whole cohort. Below the sample floor we do nothing, so
one unlucky office behind a shared IP is never condemned on two bad logins.

The gap this leaves, which the next round's attack drives through: an attacker who
(a) pre-cleans the combo list so every account exists, and (b) spreads attempts
across hundreds of cohorts so none reaches MIN_SAMPLE, shows neither ratio. The
aggregate is still anomalous — you just have no cohort precise enough to punish
without challenging everyone.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from defenses import ratelimit  # noqa: E402

WINDOW_S = 600          # 10-minute rolling view of a cohort
MIN_SAMPLE = 30         # don't judge a cohort below this many attempts
FAIL_RATIO = 0.60       # >60% failures in a stuffing-sized sample is damning
UNKNOWN_RATIO = 0.50    # >50% of attempts naming non-existent accounts
FLAG_TTL_S = 1800       # once flagged, a cohort stays challenged for 30 min


def pre_auth(ctx) -> str | None:
    if ctx["rds"].get(f"co:flag:{ctx['cohort']}"):
        return "cohort flagged for interactive challenge"
    return None


def record(ctx, ok: bool) -> str | None:
    rds, cohort = ctx["rds"], ctx["cohort"]
    attempts = ratelimit.incr_window(rds, f"co:att:{cohort}", WINDOW_S, ctx["now"])
    fails = int(rds.get(f"co:fail:{cohort}") or 0)
    unknown = int(rds.get(f"co:unk:{cohort}") or 0)
    if not ok:
        fails = ratelimit.incr_window(rds, f"co:fail:{cohort}", WINDOW_S, ctx["now"])
    if ctx["user"] is None:
        unknown = ratelimit.incr_window(rds, f"co:unk:{cohort}", WINDOW_S, ctx["now"])

    if attempts >= MIN_SAMPLE and (
        fails / attempts > FAIL_RATIO or unknown / attempts > UNKNOWN_RATIO
    ):
        rds.setex(f"co:flag:{cohort}", FLAG_TTL_S, "1")
        return (
            f"cohort {cohort}: {fails}/{attempts} failed, "
            f"{unknown}/{attempts} unknown accounts"
        )
    return None
