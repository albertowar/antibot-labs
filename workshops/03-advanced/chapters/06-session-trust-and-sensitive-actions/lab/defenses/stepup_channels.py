"""
stepup_channels (Round 3): ask for the factor that matches the weight, from the channels the account has.

Round 2 treated every second factor as strong, and a crew that holds the webmail beat it. Round 3 ranks the
factors by WHICH CREW ALREADY HOLDS THEM, then by what the account has on file:

    factor            strength   held by (the crews of Chapter 6)           needs on file
    sudo (password)      55      premium, mailbox  (every kit but session)   nothing
    otp_session (email)  55      mailbox, inbox                              the inbox (NIST SP 800-63B-4 3.1.3.1:
                                                                             email is not an out-of-band authenticator)
    kba                  65      anyone who can read the account page        questions about the store's own data
    sms_otp              80      nobody (SIM swap stays theory here)         a phone number on file
    device_confirm       90      nobody                                      an enrolled device (number matching)

A session whose trust is below the action's weight is asked for the best factor the account can answer:
the device first (the strongest, and the owner already carries it), then SMS, and KBA only when neither is on
file and the action is not an account-takeover step (strength 65 does not reach 75). If nothing reaches
the weight the action is refused: Round 4 turns that refusal into a cooling-off.

policy.FACTOR_STRENGTH holds the numbers. KBA is the honest weak spot: see attacks/round3_kba.py.

Your job (everything else is written): STRENGTHS and factor_for().
Reference: solutions/round3/defenses/stepup_channels.py (or `checkpoint.py --round 3 --catch-up`)
"""

from . import policy, session_trust, trustlib
from .pipeline import Check

STRENGTHS = session_trust.FIRST_MODEL      # TODO (Round 3): policy.FACTOR_STRENGTH (email 55, KBA 65, SMS 80, device 90)


def factor_for(need, channels, strengths=None):
    # TODO (Round 3): the table above.
    #   need <= strengths["sudo"]            -> "sudo"
    #   else the first of device_confirm (channels["device"]), sms_otp (channels["phone"]) whose strength reaches `need`
    #   else "kba" if strengths["kba"] >= need (neither channel on file), else None
    # Until you write it, Round 3 behaves like Round 2.
    return session_trust.factor_for(need)


def _check(ctx):
    if ctx.level != 3:
        return None
    st = ctx.attrs.get("st")
    if st is None:
        return None
    t = session_trust.trust(st, STRENGTHS)
    trustlib.restrict(ctx, t)
    need = trustlib.weight(ctx)
    if not need or t >= need:
        return None
    factor = factor_for(need, st["channels"], STRENGTHS)
    return trustlib.ask(ctx, factor, t, need) if factor else trustlib.refuse(ctx, t, need, "no_strong_factor")


CHECK = Check("stepup_channels", _check, phases=("request", "action:*"))
