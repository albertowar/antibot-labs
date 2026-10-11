"""L4 reference: device + network context, and re-auth for sensitive actions.

Breach screening (L3) stops stuffing but not a *fresh* credential — one an
infostealer lifted straight from the victim's browser, never breached, perfectly
correct. What still separates the thief from the owner is context: the attacker
replays the password from a different network, and usually a different device.

So on an otherwise-clean login we compare this attempt against what we have seen
for the account before:

  * device cookie (``did``) we have issued to this user,
  * the ASN the login comes from,
  * the client signature (the TLS/fingerprint summary from W2 Ch4-5).

A brand-new device, or a known device arriving over a never-seen ASN, earns a
step-up. A returning user on a remembered device and network sails through, which
is what keeps this from taxing everyone. ``remember`` records the context after a
fully clean login so the *next* visit is frictionless.

And because a stolen *session cookie* skips the login entirely (see the final
round), sensitive changes get their own gate: ``needs_reauth`` forces a fresh
proof of possession before an email or address change, no matter how the session
was obtained. This does not stop cookie theft — only DBSC, passkeys and session
anomaly models (W2 Ch7) do — but it blunts what the thief can *do* with it.
"""

from __future__ import annotations

DEVICE_TTL_S = 90 * 24 * 3600   # remember a device/network for 90 days


def _uid(ctx):
    return ctx["user"].id


def assess(ctx) -> str | None:
    rds = ctx["rds"]
    uid = _uid(ctx)
    did, asn = ctx.get("device_id"), ctx.get("asn")

    known_device = bool(did) and rds.sismember(f"dev:{uid}", did)
    known_asn = bool(asn) and rds.sismember(f"asn:{uid}", asn)
    seen_user_before = rds.exists(f"asn:{uid}")

    if not seen_user_before:
        # First login we have ever recorded for this account: nothing to compare
        # against, so trust it and start a history rather than challenge day one.
        return None
    if not known_device:
        return "login from an unrecognized device — step up"
    if not known_asn:
        return "known device over a never-seen network (ASN) — step up"
    return None


def remember(ctx) -> None:
    rds = ctx["rds"]
    uid = _uid(ctx)
    if ctx.get("device_id"):
        rds.sadd(f"dev:{uid}", ctx["device_id"])
        rds.expire(f"dev:{uid}", DEVICE_TTL_S)
    if ctx.get("asn"):
        rds.sadd(f"asn:{uid}", ctx["asn"])
        rds.expire(f"asn:{uid}", DEVICE_TTL_S)
    if ctx.get("client_sig"):
        rds.sadd(f"sig:{uid}", ctx["client_sig"])
        rds.expire(f"sig:{uid}", DEVICE_TTL_S)


def needs_reauth(user, ctx) -> bool:
    """A sensitive action needs a *fresh* proof of possession, not just a session.

    This is what defeats a stolen session cookie: the thief has the cookie but not
    the password or the second factor, so they cannot satisfy the re-auth even
    though ``/api/account`` happily served them the profile. Returns True (block)
    unless the request carries a valid TOTP code or the current password.
    """
    import pyotp
    from werkzeug.security import check_password_hash

    token = ctx.get("reauth_totp") or ""
    if user.totp_secret and token and pyotp.TOTP(user.totp_secret).verify(token, valid_window=1):
        return False
    pw = ctx.get("reauth_password") or ""
    if pw and check_password_hash(user.password_hash, pw):
        return False
    return True
