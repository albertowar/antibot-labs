"""
account_limit (Round 4): cap login attempts per TARGET account, from any address.

    policy.ACCOUNT_LIMIT = (attempts, window)    5 attempts per 15 minutes
    policy.ACCOUNT_RETRY_AFTER                   what the 429 says; the window is the real wait

endpoint_limit keys on the source address, so it does nothing when the attacker rotates
addresses but keeps hammering ONE account (the `--brute` run). Flip the key: count attempts
by the email being tried, in a sliding log, no matter where they come from. Six guesses at
one account in fifteen minutes is almost never a real person.

Why a sliding log (store.Counters) and not a bucket? Because the number is small and the
window is long. A log of five timestamps per targeted account is cheap, and it lets the
window slide exactly instead of resetting on a boundary an attacker could wait out.

The careful part: count on EVERY attempt, before you know if the password was right, and key
on the submitted email even if no such user exists. If you only counted failures or only real
accounts, an attacker would learn which emails are real from which ones get throttled, and
would turn your lockout into an enumeration oracle.

What it catches: one account targeted from many addresses (credential rotation, brute force).
What it misses: a stuffing run that tries each account only a few times across a huge list:
no single account crosses the threshold. That is why this sits next to, not instead of, the
per-IP limits.
Who it hurts: a real person who forgot which password they use and a flatmate retrying the
same shared account. Sized loosely (5 / 15 min) and never a block of the account itself, only
a 429 that asks them to wait: a per-account lockout you cannot clear is itself a denial of
service an attacker can aim at a victim.
"""

from . import policy
from .pipeline import Check, Signal, Verdict
from .store import Counters


def _target(ctx):
    """The account this request is trying to authenticate as (form or JSON)."""
    email = (ctx.form.get("email") or (ctx.json or {}).get("email") or "").strip().lower()
    return email or None


def _check(ctx):
    if ctx.method != "POST" or ctx.path != "/login":
        return None
    email = _target(ctx)
    if not email:
        return None
    attempts, window = policy.ACCOUNT_LIMIT
    # TODO (Round 4): count this attempt against `email` in a sliding log —
    # Counters(ctx.redis, "lab:acct").hit("login", email, window) — on EVERY attempt,
    # real account or not, BEFORE the password is checked (the docstring says why), and
    # past `attempts` return Verdict("rate_limit",
    # retry_after=policy.ACCOUNT_RETRY_AFTER, signals=(Signal("rate_limit",
    # "account_login_rate", 0, email),)).
    return None


CHECK = Check("account_limit", _check)
