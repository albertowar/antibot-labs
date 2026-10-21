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
    # TODO (Round 1): let the request through when the password was just proven, else ask for it.
    #   ctx.attrs.get("reauth")       W2 Ch6's shape: {"password_ok": bool} when the request carried the password
    #   ctx.attrs["st"]["factors"]    {"sudo": seconds since it was solved}; fresh while <= policy.FACTOR_TTL_S
    #                                 (ctx.note(sudo="fresh") so the decision log shows why)
    #   trustlib.ask(ctx, "sudo", 0.0, need)   the step-up; return what it returns
    return None           # until you write it, a session cookie alone can do everything

CHECK = Check("sudo_reauth", _check, phases=("action:*",))
