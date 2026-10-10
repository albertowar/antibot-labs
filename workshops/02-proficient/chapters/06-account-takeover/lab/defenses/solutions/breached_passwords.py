"""L3 reference: step up when a *correct* password is a known-breached one.

This is the highest-leverage control against credential stuffing, and the reason
is almost tautological: a stuffer only has passwords that already leaked. So if a
login presents the correct password *and* that password is in the breach corpus,
the credential is, by definition, stuffable — treat the login as unproven and
demand a second factor instead of minting a session.

Why screen the breach here and not only block weak passwords at registration?
Both matter. Registration screening (NIST SP 800-63B-4 §5.1.1.2 SHALL: compare
new passwords against a blocklist of compromised values) stops the account from
ever having a stuffable password. But existing accounts predate that rule, so at
login we catch the ones that slipped through — without an enumeration oracle,
because the check runs only *after* the password already verified.

Cost, stated honestly: every legitimate user whose real password happens to be in
the corpus hits the step-up too. In this lab that is ~20% of the human cohort.
In production you would prompt them to rotate, not punish them forever.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from defenses import breachcorpus  # noqa: E402


def screen(ctx) -> str | None:
    count = breachcorpus.pwned_count(ctx["password"])
    if count > 0:
        return f"correct password appears in breach corpus ({count} times) — step up"
    return None
