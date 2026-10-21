"""
trustlib: the small, finished helpers Rounds 1-4 share. Nothing in here is a decision about WHO to trust.

    weight(ctx)         how much trust the current action needs (0: none), from policy.ACTION_RISK and the
                        facts the routes put on ctx.notes (a checkout to a new address, a card that is not saved)
    ask(...)            the verdict "prove it with this factor": a challenge, with the reason in the log
    refuse(...)         the verdict "not with this session": a block
    FACTOR_CHANNEL      which channel on file each factor needs (None: none)

`ctx.attrs["st"]` is built by demo_site/ext/session_trust.py on every request (see its docstring):
{"login_base", "login_age_s", "idle_s", "drift", "factors", "channels", "methods"}.
"""

from . import policy
from .pipeline import Signal, Verdict

MASKED_PATHS = ("/api/account", "/api/orders")
FACTOR_CHANNEL = {"sudo": None, "otp_session": "email", "kba": None, "sms_otp": "phone", "device_confirm": "device"}
POINTS = 50     # the challenge band


def weight(ctx):
    """The trust the action in `ctx.phase` needs. 0 for anything that is not a sensitive action,
    for an anonymous session (there is no account to take over) and for a guest checkout."""
    if ctx.user is None or not ctx.phase.startswith("action:"):
        return 0
    action = ctx.phase.split(":", 1)[1]
    if action == "checkout":
        need = 0
        if ctx.notes.get("ship_to_new"):
            need = max(need, policy.CHECKOUT_NEW_ADDRESS)
        if ctx.notes.get("card_bin6") and not ctx.notes.get("card_saved"):
            need = max(need, policy.CHECKOUT_NEW_CARD)
        return need
    return policy.ACTION_RISK.get(action, 0)


def restrict(ctx, trust):
    """Restricted mode: below policy.MASK_BELOW the account page is masked on the way out (the ext does it).
    Browsing and buying to an address on file with the saved card stay open; the sensitive actions do not."""
    if ctx.phase == "request" and ctx.path in MASKED_PATHS and trust < policy.MASK_BELOW:
        ctx.attrs["mask"] = True


def ask(ctx, factor, trust, need):
    """Challenge for `factor`. The clearance a previous solve left is revoked first: the downgrade
    rule (contract 4.3) would otherwise absorb this verdict for the clearance's whole lifetime."""
    from demo_site import gate
    gate.revoke_clearance(ctx, factor)
    ctx.note(trust=round(trust), need=need, factor=factor)
    return Verdict("challenge", challenge=factor,
                   signals=(Signal("trust", "below_weight", POINTS, f"trust {trust:.0f} < {need}: {factor}"),))


def refuse(ctx, trust, need, why):
    ctx.note(trust=round(trust), need=need, factor="none")
    return Verdict("block", signals=(Signal("trust", why, 100, f"trust {trust:.0f} < {need}"),))
