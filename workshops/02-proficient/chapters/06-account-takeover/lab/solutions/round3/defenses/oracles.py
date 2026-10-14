"""
oracles (Round 3): stop telling attackers which accounts exist.

Breach screening only helps if the attacker still has to try the WHOLE combo list. The moment an
endpoint says which accounts exist, they prune the list to real users and the attack gets an order
of magnitude cheaper (and far quieter: no unknown-account ratio left for Round 2's check to see).

This store has one deliberate leak, the legacy `POST /api/account/recover` that a long-gone mobile
app still calls: "Recovery link sent" for a real address, "No account with that email" (404) for
the rest. The fix is the same answer for everyone, which is what the main password reset
(`/api/password-reset`) already does. Closing the leak is one flag: the route reads
`ctx.attrs["uniform_recover"]` and answers identically when it is set.

The other classic oracle, timing, is already closed in the starter: `check_password` hashes the
password against a dummy value when the account does not exist, so an unknown email costs what a
real one does. Registration ("that email is already registered") and username-taken messages are
the oracles production stores forget; they need rate limits and a CAPTCHA, because a sign-up form
has to say something.

Who it hurts: the honest user who mistyped their email now gets the same "if that address exists"
message and has to check their inbox. That is the price, and it is a small one.
"""

from .pipeline import Check


def _check(ctx):
    ctx.attrs["uniform_recover"] = True
    return None


CHECK = Check("oracles", _check, phases=("action:recover",))
