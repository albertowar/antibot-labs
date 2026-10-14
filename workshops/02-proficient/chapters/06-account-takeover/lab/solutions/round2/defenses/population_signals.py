"""
population_signals (Round 2): per-cohort failure and unknown-account ratios.

A distributed stuffer rotates IPs so no single address looks busy, but the run still shares
SOMETHING: a rented /24, an ASN, a hosting provider. Group the attempts by that cohort (the /24 for
IPv4, the /64 for IPv6: the smallest block most networks route and reassign) and two ratios give
it away:

  * failure ratio: stuffing tests mostly-wrong passwords, so failures dominate.
  * unknown-account ratio: combo lists are full of emails that were never your users, so most
    attempts name accounts that do not exist.

Either ratio, once a cohort has enough attempts to be worth judging (MIN_SAMPLE), latches a
challenge on the whole cohort for FLAG_TTL_S. Below the sample floor we do nothing, so one
unlucky office behind a shared IP is never condemned on two bad logins.

The gap it leaves, which Round 2's attacker drives through: an attacker who (a) pre-cleans the
combo list so every account exists, and (b) spreads attempts across hundreds of cohorts so none
reaches MIN_SAMPLE, shows neither ratio. The aggregate is still anomalous; you just have no cohort
precise enough to punish without challenging everyone.

Who it hurts: a cohort that really is a crowd. A university or a mobile carrier's /24 has a high
share of typos and lapsed passwords on Monday morning. The sample floor and the ratios are the
trade-off: lower them and the first noisy office is flagged.

A flagged cohort gets a challenge. The lab registers no solver for it, so the gate enforces it as
a block: the cost of an unavailable challenge is visible. A successful login that is the one to trip
the flag is refused too (the password was right, but the cohort is not), whereas a failed one just
returns its 401.
"""

from . import ratelimit, store
from .pipeline import Check, Signal

WINDOW_S = 600          # 10-minute rolling view of a cohort
MIN_SAMPLE = 30         # do not judge a cohort below this many attempts
FAIL_RATIO = 0.60       # more than 60 % failures in a stuffing-sized sample is damning
UNKNOWN_RATIO = 0.50    # more than 50 % of attempts naming accounts that do not exist
FLAG_TTL_S = 1800       # once flagged, a cohort stays challenged for 30 min
POINTS = 45             # the challenge band (policy.BANDS): a challenge, not a block


def _flagged(ctx):
    return [Signal("population", "cohort_flagged", POINTS, f"cohort {store.prefix_of(ctx.ip)} is latched")]


def _pre_auth(ctx):
    if ctx.redis.get(f"lab:ato:co:flag:{store.prefix_of(ctx.ip)}"):
        return _flagged(ctx)
    return None


def _record(ctx):
    login = ctx.attrs.get("login")
    if not login:
        return None
    rds, cohort = ctx.redis, store.prefix_of(ctx.ip)
    attempts = ratelimit.incr_window(rds, f"lab:ato:co:att:{cohort}", WINDOW_S)
    fails = int(rds.get(f"lab:ato:co:fail:{cohort}") or 0)
    unknown = int(rds.get(f"lab:ato:co:unk:{cohort}") or 0)
    if not login["ok"]:
        fails = ratelimit.incr_window(rds, f"lab:ato:co:fail:{cohort}", WINDOW_S)
    if not login["known"]:
        unknown = ratelimit.incr_window(rds, f"lab:ato:co:unk:{cohort}", WINDOW_S)
    if attempts >= MIN_SAMPLE and (fails / attempts > FAIL_RATIO or unknown / attempts > UNKNOWN_RATIO):
        rds.setex(f"lab:ato:co:flag:{cohort}", FLAG_TTL_S, "1")
        if login["ok"]:
            return _flagged(ctx)
    return None


def _check(ctx):
    return _pre_auth(ctx) if ctx.phase == "action:login" else _record(ctx)


CHECK = Check("population_signals", _check, phases=("action:login", "action:login_result"))
