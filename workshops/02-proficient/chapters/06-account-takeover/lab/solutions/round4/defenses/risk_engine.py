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
through, which is what keeps this from taxing everyone. `_remember` records the context after a
fully clean login so the next visit is frictionless; the first login we ever record for an account
is trusted (trust on first use), because there is nothing to compare it with.

And because a stolen SESSION cookie skips the login entirely (Round 4's attacker), sensitive
changes get their own gate, REAUTH: an email change needs a fresh proof of possession (the current
password) no matter how the session was born. This does not stop the cookie theft. Only
device-bound sessions (DBSC), passkeys and session-anomaly models do (W2 Ch7). It blunts what the
thief can DO with the session.

Who it hurts: anyone on a new phone, a new laptop, a hotel or a different VPN exit, who now enters
a code; and everyone who clears cookies (the device id is gone). The honest numbers are in the
checkpoint's "stepped up" column. A device cookie is also copyable (the infostealer copies it
too), so it is the network, not the cookie, that does the work against Round 3's attacker.
"""

from .pipeline import Check, Signal, Verdict

DEVICE_TTL_S = 90 * 24 * 3600       # remember a device and network for 90 days
POINTS = 50                         # the challenge band: a step-up, not a block


def _login_result(ctx):
    login = ctx.attrs.get("login")
    if not login or not login["ok"] or ctx.user is None:
        return None
    rds, uid = ctx.redis, ctx.user.id
    did, asn = ctx.cookies.get("did", ""), str(ctx.edge.asn)
    seen_before = rds.exists(f"lab:ato:asn:{uid}")
    if seen_before:
        reason = None
        if not (did and rds.sismember(f"lab:ato:dev:{uid}", did)):
            reason = ("unrecognized_device", "login from a device this account has not used")
        elif not rds.sismember(f"lab:ato:asn:{uid}", asn):
            reason = ("new_network", "known device over a never-seen network (ASN)")
        if reason:
            ctx.attrs["stepup"] = True
            return Verdict("challenge", challenge="otp", signals=(Signal("risk", reason[0], POINTS, reason[1]),))
    if not ctx.attrs.get("stepup"):             # a fully clean login: remember it
        if did:
            rds.sadd(f"lab:ato:dev:{uid}", did)
            rds.expire(f"lab:ato:dev:{uid}", DEVICE_TTL_S)
        rds.sadd(f"lab:ato:asn:{uid}", asn)
        rds.expire(f"lab:ato:asn:{uid}", DEVICE_TTL_S)
    return None


def _reauth(ctx):
    if (ctx.attrs.get("reauth") or {}).get("password_ok"):
        return None
    return Verdict("challenge", challenge="reauth",
                   signals=(Signal("risk", "reauth_required", POINTS, "sensitive change without a fresh proof"),))


CHECK = Check("risk_engine", _login_result, phases=("action:login_result",))
REAUTH = Check("reauth", _reauth, phases=("action:change_email",))
