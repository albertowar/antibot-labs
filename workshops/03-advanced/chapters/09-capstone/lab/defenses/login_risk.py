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

Where it fails:
  - Identical corporate laptops share a fingerprint hash; one user locked out by typos can drag the
    cluster's ratio up. That is what the minimum count is for.
  - A stuffer that presents a new fingerprint per attempt makes every attempt its own cluster, so the
    ratio never accumulates (attacks/round4_stuffing.py --rotate-fp). Counting across clusters without
    blocking the shared office NAT needs something the browser cannot forge about the device:
    attestation, which is W3 Ch1.
"""

import hashlib

from . import ja4, policy, ratelimit, sensor, token_binding
from .pipeline import Check, Signal


def cluster_of(ctx):
    fp = token_binding.fingerprint_hash(sensor.report(ctx)) or "no-fingerprint"
    return f"{ja4.fingerprint(ctx).ja4_ab}|{fp}"


def _keys(ctx):
    cid = hashlib.sha256(cluster_of(ctx).encode()).hexdigest()[:12]
    return f"lab:lr:{cid}:total", f"lab:lr:{cid}:fail"


def counts(ctx):
    total_key, fail_key = _keys(ctx)
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
    total_key, fail_key = _keys(ctx)
    ratelimit.incr_window(ctx.redis, total_key, policy.CLUSTER_WINDOW_S)
    if not login["ok"]:
        ratelimit.incr_window(ctx.redis, fail_key, policy.CLUSTER_WINDOW_S)
    return None


def _check(ctx):
    return _pre_auth(ctx) if ctx.phase == "action:login" else _record(ctx)


CHECK = Check("login_risk", _check, phases=("action:login", "action:login_result"))
