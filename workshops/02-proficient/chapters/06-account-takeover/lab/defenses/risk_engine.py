"""
risk_engine (Round 4): device and network context at login, and fresh proof for sensitive changes.

Breach screening stops stuffing, not a FRESH credential: one an infostealer lifted straight from
the victim's browser, never breached, perfectly correct. What still separates the thief from the
owner is context. The attacker replays the password from a different network, and usually from a
different device. So on an otherwise-clean login we compare this attempt with what we have seen
for the account:

  * the device cookie (`did`) the store issued to this browser,
  * the ASN the login comes from (`ctx.edge.asn`).

A device we have never seen, or a known device arriving over a never-seen ASN, earns the same
emailed-code step-up as Round 3. A returning user on a remembered device and network sails
through, which is what keeps this from taxing everyone. `_login_result` records the context after
a fully clean login so the next visit is frictionless; the first login we ever record for an
account is trusted (trust on first use), because there is nothing to compare it with.

And because a stolen SESSION cookie skips the login entirely (Round 4's attacker), sensitive
changes get their own gate, REAUTH: an email change needs a fresh proof of possession (the current
password) no matter how the session was born. This does not stop the cookie theft. Only
device-bound sessions (DBSC), passkeys and session-anomaly models do (W2 Ch7). It blunts what the
thief can DO with the session.

Who it hurts: anyone on a new phone, a new laptop, a hotel or a different VPN exit, who now enters
a code; and everyone who clears cookies (the device id is gone). The honest numbers are in the
checkpoint's "stepped up" column. A device cookie is also copyable (the infostealer copies it
too), so it is the network, not the cookie, that does the work against Round 3's attacker.

Redis shape: sets `lab:ato:dev:<user id>` (device ids) and `lab:ato:asn:<user id>` (ASNs).
Reference: solutions/round4/defenses/risk_engine.py (or `checkpoint.py --round 4 --catch-up`)
"""

from .pipeline import Check, Signal, Verdict

DEVICE_TTL_S = 90 * 24 * 3600       # remember a device and network for 90 days
POINTS = 50                         # the challenge band: a step-up, not a block


def _login_result(ctx):
    login = ctx.attrs.get("login")      # {"ok": bool, "email": str, "known": bool, "password": str}
    if not login or not login["ok"] or ctx.user is None:
        return None
    # TODO (Round 4): compare ctx.cookies.get("did") and str(ctx.edge.asn) with the account's history
    #   (the two sets above, for ctx.user.id).
    #   - No history yet (the asn set does not exist): trust this login.
    #   - A device that is not in the set, or a known device over an ASN that is not: set
    #     ctx.attrs["stepup"] = True and return Verdict("challenge", challenge="otp",
    #     signals=(Signal("risk", "<unrecognized_device|new_network>", POINTS, <detail>),)).
    #   - Otherwise, and only if ctx.attrs.get("stepup") is not set (Round 3 may have set it),
    #     remember the device and ASN (sadd + expire DEVICE_TTL_S) so the next visit is clean.
    return None


def _reauth(ctx):
    proof = ctx.attrs.get("reauth") or {}   # the route verified the request's `password`: {"password_ok": bool}
    # TODO (Round 4): unless proof.get("password_ok"), return
    #   Verdict("challenge", challenge="reauth", signals=(Signal("risk", "reauth_required", POINTS, <detail>),)).
    #   Until you do, sensitive actions are allowed through: exactly the gap Round 4's attacker uses.
    return None


CHECK = Check("risk_engine", _login_result, phases=("action:login_result",))
REAUTH = Check("reauth", _reauth, phases=("action:change_email",))
