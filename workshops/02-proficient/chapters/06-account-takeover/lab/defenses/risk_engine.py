"""L4: device + network context, and re-auth for sensitive actions.  <-- Round 4.

Fill in the TODOs so that an otherwise-clean login is stepped up when it comes
from an unrecognized device or a known device over a never-seen ASN — but a
returning user on a remembered device and network is not. ``remember`` must
record the context after a clean login so the next visit is frictionless, and
``needs_reauth`` gates sensitive changes regardless of how the session was born.

Redis shape used by the reference: sets ``dev:<uid>`` (device ids),
``asn:<uid>`` (ASNs) and ``sig:<uid>`` (client signatures).

Reference solution: defenses/solutions/risk_engine.py
"""

from __future__ import annotations

DEVICE_TTL_S = 90 * 24 * 3600


def assess(ctx) -> str | None:
    # TODO (Round 4): compare ctx["device_id"] / ctx["asn"] against the account's
    #   history (sets dev:<uid> / asn:<uid>). First-ever login (no history yet)
    #   should pass. Unknown device, or known device over a new ASN, returns a
    #   step-up reason.
    return None


def remember(ctx) -> None:
    # TODO (Round 4): add the device id, ASN and client signature to the account's
    #   history sets (with DEVICE_TTL_S expiry).
    return None


def needs_reauth(user, ctx) -> bool:
    # TODO (Round 4): return True (block) unless the request carries a valid fresh
    #   proof — a correct TOTP code (ctx["reauth_totp"]) or the current password
    #   (ctx["reauth_password"]). Until you implement it, sensitive actions are
    #   allowed through, which is exactly the gap the session-replay attack uses.
    return False
