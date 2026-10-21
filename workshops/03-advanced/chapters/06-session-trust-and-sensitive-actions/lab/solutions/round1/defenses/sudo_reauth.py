"""
sudo_reauth (Round 1): re-enter the password before any sensitive action, once per window.

This is the control W2 Ch6 section 6.5 hard-coded on change_email, made general and given a window the way
GitHub's "sudo mode" does (two hours there; policy.FACTOR_TTL_S on the lab clock here): the first sensitive
action in a window asks for the password, the next ones in the window do not. OWASP ASVS 5.0.0 V7.5.1
asks for full re-authentication before changes to email, phone number, MFA or recovery details.

It is level-gated (Round 1 only): from Round 2 the trust model decides, and the password is one of its factors.

    weight(ctx)                 trustlib: 0 for browsing, 50-75 for the sensitive actions (policy.ACTION_RISK)
    the "sudo" challenge        demo_site/ext/session_trust.py: verifies the password, five tries a window
    ctx.attrs["st"]["factors"]  {"sudo": seconds since it was solved}, on the lab clock

What it stops: a session cookie on its own (no password). What it does not stop: anyone who holds the
password, which is every crew that survived Chapter 5's login.
"""

from . import policy, trustlib
from .pipeline import Check


def _check(ctx):
    if ctx.level != 1:
        return None
    need = trustlib.weight(ctx)
    if not need:
        return None
    reauth = ctx.attrs.get("reauth")                       # W2 Ch6's shape: a password sent with the request itself
    if reauth and reauth.get("password_ok"):
        return None
    st = ctx.attrs.get("st") or {}
    age = (st.get("factors") or {}).get("sudo")
    if age is not None and age <= policy.FACTOR_TTL_S:
        ctx.note(sudo="fresh")
        return None
    return trustlib.ask(ctx, "sudo", 0.0, need)


CHECK = Check("sudo_reauth", _check, phases=("action:*",))
