"""
breached_passwords (Round 1): a correct password that is in a breach corpus is not proof of the owner.

The economics. A combo list IS a breach dump, so every credential a stuffer can use successfully
is, by construction, a password that has already leaked. Gate on that fact and every stuffing hit
turns into friction instead of a takeover, without the defender ever deciding "this was a bot".

Where it runs. After the password is verified, never before: telling a client "that password is
breached" on a WRONG guess would be an enumeration oracle. The starter checks a request before the
route runs, so demo_site/ext/step_up.py adds a second phase, `action:login_result`, with the
outcome in ctx.attrs["login"] = {"ok", "email", "known", "password"}. If this check asks for a
challenge, the ext takes the session back and the store emails a six-digit code (read it in
/lab/mailbox/<email>); the session exists only after POST /api/challenge/verify.

Who it hurts. Every real customer whose real password is in the corpus gets the same step. In this
lab that is two of the 40 shoppers (users 020 and 021). They enter the code and get in: friction,
not harm, and a prompt to rotate the password is what you would add next.

What it misses. Credentials that never leaked: an infostealer reads the password out of the
victim's browser, so the corpus has never seen it (W2 Ch6).

Helper (finished): breachcorpus.pwned_count(password) -> times seen in the corpus (0 = not there)
Reference: solutions/round1/defenses/breached_passwords.py (or `checkpoint.py --round 1 --catch-up`)
"""

from . import breachcorpus
from .pipeline import Check, Signal, Verdict

POINTS = 50      # the challenge band (40 to 74): a step-up, not a block


def _check(ctx):
    login = ctx.attrs.get("login")       # {"ok": bool, "email": str, "known": bool, "password": str}
    if not login or not login["ok"]:
        return None
    # TODO (Round 1): if login["password"] is in the corpus (breachcorpus.pwned_count), return
    #   Verdict("challenge", challenge="otp", signals=(Signal("breached_password", "in_corpus", POINTS, <detail>),))
    # Otherwise return None. Do not look at the password of a failed login.
    return None


CHECK = Check("breached_passwords", _check, phases=("action:login_result",))
