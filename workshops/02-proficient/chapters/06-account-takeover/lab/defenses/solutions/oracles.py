"""L3 reference: close the account-enumeration oracles.

Breach screening only helps if the attacker still has to test the *whole* combo
list. The moment your endpoints tell them which accounts exist, they prune the
list to real users and the attack gets an order of magnitude cheaper. Two leaks
to close:

  * Response oracle — ``/forgot-password`` that says "no such user" for a missing
    account and "email sent" for a real one. Return the *same* answer either way.
  * Timing oracle — a missing account skips password hashing and answers in
    microseconds, while a real account spends milliseconds in the KDF. Burn the
    same work on a dummy hash when the account does not exist, so the clock tells
    the attacker nothing.

Enumeration is also why breached-password checks belong *after* authentication,
never before: a "your password is breached, reset it" shown on a wrong password
is itself an oracle. L3's screen (breached_passwords) runs only once the password
has already verified.
"""

from __future__ import annotations

import os
import sys

from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from defenses.labhash import hash_pw  # noqa: E402

# Pre-computed once: a valid hash of a value no account uses, at the same cost as a
# real account hash. Verifying any password against it does the full KDF work and
# always returns False — which is exactly how it equalizes the timing oracle.
DUMMY_HASH = hash_pw("lab-dummy-password-not-in-use")


def equalize_timing(password: str) -> None:
    """Spend one KDF verification so a missing account costs what a real one does."""
    check_password_hash(DUMMY_HASH, password or "")


def forgot_password_response() -> dict:
    """The hardened, identical-for-everyone response."""
    return {"status": "ok", "message": "If that account exists, we've sent a reset link."}
