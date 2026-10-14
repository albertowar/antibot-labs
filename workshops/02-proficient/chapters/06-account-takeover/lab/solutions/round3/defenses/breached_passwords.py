"""
breached_passwords (Round 3): when a CORRECT password is a known-breached one, do not trust the login.

This is the highest-leverage control against credential stuffing, and the reason is almost a
tautology: a stuffer only has passwords that already leaked. If a login presents the correct
password AND that password is in the breach corpus, the credential is stuffable by definition, so
treat the login as unproven and demand a second proof (a code emailed to the account) before any
session exists.

Why screen at login and not only at registration? Both matter. Registration screening (NIST SP
800-63B-4 requires comparing new passwords against a list of compromised values) stops an account
from ever holding a stuffable password. But existing accounts predate that rule, so at login we
catch the ones that slipped through. And the screen runs only AFTER the password verified: telling
someone "that password is breached" on a wrong guess would itself be an enumeration oracle.

Who it hurts: every real user whose actual password is in the corpus gets the extra step too. In
this lab that is the 12 humans playing users 018-029. They finish it and get in, so count it as
friction, not a block; in production you would prompt them to rotate and stop punishing them.

What it misses: credentials that were never breached. An infostealer reads the password straight
out of the victim's browser, so the corpus has never seen it. That is Round 3's attacker.
"""

from . import breachcorpus
from .pipeline import Check, Signal, Verdict

POINTS = 50     # the challenge band: a step-up, not a block


def _check(ctx):
    login = ctx.attrs.get("login")
    if not login or not login["ok"]:
        return None
    seen = breachcorpus.pwned_count(login["password"])
    if not seen:
        return None
    ctx.attrs["stepup"] = True          # the risk engine (Round 4) must not "remember" this login
    return Verdict("challenge", challenge="otp",
                   signals=(Signal("breached_password", "in_corpus", POINTS, f"correct password seen {seen} times in the corpus"),))


CHECK = Check("breached_passwords", _check, phases=("action:login_result",))
