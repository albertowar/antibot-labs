"""L3: close the account-enumeration oracles.  <-- you harden these in Round 3.

Two leaks to close at L3:
  * /forgot-password must answer identically whether or not the account exists
    (``forgot_password_response``).
  * A missing account must cost the same KDF time as a real one, so the response
    clock is not a timing oracle (``equalize_timing``).

The timing guard is called from the login pipeline; the response is called from
app.py. Fill in the TODOs. Reference: solutions/round3/defenses/oracles.py
"""

from __future__ import annotations

import os
import sys

from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from defenses.labhash import hash_pw  # noqa: E402

# Same method/cost as real account hashes, so equalize_timing actually equalizes.
DUMMY_HASH = hash_pw("lab-dummy-password-not-in-use")


def equalize_timing(password: str) -> None:
    # TODO (Round 3): verify ``password`` against DUMMY_HASH to burn one KDF pass.
    return None


def forgot_password_response() -> dict:
    # TODO (Round 3): return the same response for every address.
    return {"status": "ok", "message": "If that account exists, we've sent a reset link."}
