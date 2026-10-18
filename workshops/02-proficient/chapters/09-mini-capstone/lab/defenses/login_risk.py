"""
login_risk (Round 4): failures per fingerprint cluster. Enabled at DEFENSE_LEVEL >= 5.

Credential stuffing has one statistical signature no proxy pool can hide: most attempts fail. Real users
mistype now and then; a combo list fails 90 to 99 % of the time. The question is what to count failures
PER:

    per IP            useless once the attacker rotates residential proxies (login_throttle, W2 Ch6,
                      is the per-IP and per-account layer, and it is on at level 1)
    per account       catches brute force, not stuffing (one try per account)
    per fingerprint   what token binding makes possible: every attempt is tied to one JA4 and one
                      fingerprint hash, and a stuffer replays one captured fingerprint or runs one
                      browser build. W2 Ch6's population_signals counts per /24 network cohort; this
                      is the same idea keyed on the device instead of the network.

    cluster = JA4 a+b + fingerprint hash
    >= CLUSTER_MIN_FAILURES failures AND failure ratio >= CLUSTER_MAX_FAILURE_RATIO in CLUSTER_WINDOW_S
        ->  CLUSTER_POINTS (a block)

It decides BEFORE the password is verified (phase `action:login`), and counts the outcome afterwards
(phase `action:login_result`, which W2 Ch6's ext/ato.py runs after the route has answered). That order
matters: a step-up ("we emailed you a code") only answers after a correct password, so a stuffer that
sees step-up replies has still learned which credentials work and can sell them. Blocking the cluster
first means it learns nothing more.

Where the cluster rule fails:
  - Identical corporate laptops share a fingerprint hash; one user locked out by typos can drag the
    cluster's ratio up. That is what the minimum count is for.
  - A stuffer that presents a new fingerprint per attempt makes every attempt its own cluster, so the
    ratio never accumulates (attacks/round4_stuffing.py --rotate-fp).

The CAMPAIGN rule answers that rotation, and pays for it. A second pair of counters is keyed one
level up, on the JA4 a+b alone — the browser-family-and-build the attacker claims, which rotation
does not change (change it and you land in a family you don't match, which is Round 1's check).
When the family's failures trip CAMPAIGN_MIN_FAILURES and CAMPAIGN_FAILURE_RATIO, a login that
SUCCEEDS from a cluster that has never signed anyone in before is stepped up to the `otp` challenge:
the code lands in the account owner's inbox, which a stuffer does not hold. Two prices, stated
plainly, because every real Chrome shares this family:
  - an oracle: the step-up only appears after a correct password, so the attacker learns which pairs
    are valid even though it cannot finish the sign-in. W2 Ch6 Round 4 made the same trade. The
    cluster rule above deliberately does NOT make it, which is why both exist.
  - collateral friction: while a campaign is running, a real customer on a brand-new device is asked
    for the code too. Their known device (a cluster with a past success) sails through.
Removing both prices needs something the browser cannot forge about the device: attestation,
which is W3 Ch1.
"""

import hashlib

from . import ja4, policy, ratelimit, sensor, token_binding
from .pipeline import Check, Signal, Verdict


def cluster_of(ctx):
    fp = token_binding.fingerprint_hash(sensor.report(ctx)) or "no-fingerprint"
    return f"{ja4.fingerprint(ctx).ja4_ab}|{fp}"


def family_of(ctx):
    return ja4.fingerprint(ctx).ja4_ab or "no-ja4"


def _keys(ctx):
    cid = hashlib.sha256(cluster_of(ctx).encode()).hexdigest()[:12]
    return f"lab:lr:{cid}:total", f"lab:lr:{cid}:fail"


def _family_keys(ctx):
    fid = hashlib.sha256(family_of(ctx).encode()).hexdigest()[:12]
    return f"lab:lrf:{fid}:total", f"lab:lrf:{fid}:fail"


def counts(ctx):
    total_key, fail_key = _keys(ctx)
    return int(ctx.redis.get(total_key) or 0), int(ctx.redis.get(fail_key) or 0)


def family_counts(ctx):
    total_key, fail_key = _family_keys(ctx)
    return int(ctx.redis.get(total_key) or 0), int(ctx.redis.get(fail_key) or 0)


def _pre_auth(ctx):
    total, failures = counts(ctx)
    ctx.note(cluster_total=total, cluster_failures=failures)
    if failures >= policy.CLUSTER_MIN_FAILURES and failures / max(1, total) >= policy.CLUSTER_MAX_FAILURE_RATIO:
        return [Signal("login_risk", "cluster_failing", policy.CLUSTER_POINTS,
                       f"this fingerprint cluster failed {failures} of its last {total} logins")]
    return None


def _record(ctx):
    login = ctx.attrs.get("login")
    if not login:
        return None
    for total_key, fail_key in (_keys(ctx), _family_keys(ctx)):
        ratelimit.incr_window(ctx.redis, total_key, policy.CLUSTER_WINDOW_S)
        if not login["ok"]:
            ratelimit.incr_window(ctx.redis, fail_key, policy.CLUSTER_WINDOW_S)
    return None


def _step_up(ctx):
    """The campaign rule: a correct password, from a device that has never signed anyone in, while the
    family's failures are burning -> ask for the emailed code. Reads the counters BEFORE _record adds
    this attempt, so 'never signed anyone in' means before this login."""
    login = ctx.attrs.get("login")
    if not login or not login["ok"]:
        return None
    f_total, f_failures = family_counts(ctx)
    if f_failures < policy.CAMPAIGN_MIN_FAILURES or f_failures / max(1, f_total) < policy.CAMPAIGN_FAILURE_RATIO:
        return None
    total, failures = counts(ctx)
    if total - failures > 0:                             # a device with a past success: a known device
        return None
    ctx.note(campaign_family_failures=f_failures, campaign_family_total=f_total)
    return Verdict(signals=(Signal("login_risk", "campaign_stepup", policy.CAMPAIGN_POINTS,
                                   f"correct password on a first-seen device while this family failed "
                                   f"{f_failures} of its last {f_total} logins"),), challenge="otp")


def _check(ctx):
    if ctx.phase == "action:login":
        return _pre_auth(ctx)
    v = _step_up(ctx)
    _record(ctx)
    return v


CHECK = Check("login_risk", _check, phases=("action:login", "action:login_result"))
