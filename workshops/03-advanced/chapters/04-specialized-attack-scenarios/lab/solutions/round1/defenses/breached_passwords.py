"""
breached_passwords (Round 1, reference): a correct password that is in a breach corpus is not proof of the owner.

The economics. A combo list IS a breach dump, so every credential a stuffer can use successfully
is, by construction, a password that has already leaked. Gate on that fact and every stuffing hit
turns into friction instead of a takeover, without the defender ever deciding "this was a bot".

Where it runs. After the password is verified, never before: telling a client "that password is
breached" on a WRONG guess would be an enumeration oracle. The check runs in `action:login_result`
(demo_site/ext/step_up.py); asking for the `otp` challenge takes the session back and emails a code.

Who it hurts. Every real customer whose real password is in the corpus: two of the 40 shoppers here.
They enter the code and get in. In production, screen at password-set time too (NIST SP 800-63B-4
requires comparing new passwords against compromised values) so the prompt disappears as users rotate.

What it misses. Credentials that never leaked (an infostealer's output), and a corpus that is older
than the attacker's newest leak. Measure the prompt rate before you turn it on.
"""

from . import breachcorpus
from .pipeline import Check, Signal, Verdict

POINTS = 50      # the challenge band (40 to 74): a step-up, not a block


def _check(ctx):
    login = ctx.attrs.get("login")
    if not login or not login["ok"]:
        return None
    seen = breachcorpus.pwned_count(login["password"])
    if not seen:
        return None
    return Verdict("challenge", challenge="otp",
                   signals=(Signal("breached_password", "in_corpus", POINTS, f"password seen {seen}x in the corpus"),))


CHECK = Check("breached_passwords", _check, phases=("action:login_result",))
