"""L3: step up when a correct password is a known-breached one.  <-- Round 3.

The breach corpus is a local, offline mirror of the HIBP range API. Fill in the
TODO so that a *correct* login whose password appears in the corpus returns a
step-up reason instead of being allowed through to a session.

Helper (already written): ``defenses/breachcorpus.py``
    breachcorpus.pwned_count(password) -> int   # 0 means not found

Reference solution: defenses/solutions/breached_passwords.py
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from defenses import breachcorpus  # noqa: E402


def screen(ctx) -> str | None:
    # TODO (Round 3): if ctx["password"] is in the breach corpus, return a reason
    #   string (step up). Otherwise return None.
    return None
