"""
Round 3 reference: interventions at the payment moment.

The platform cannot read the off-platform chat, but it sees the moment money moves through its
wallet, and it knows what led up to it. The scam shape: a FIRST payment to someone, made by a
member whom a NEW contact (a thread started in the last 60 days) asked to move to another app
at least three days ago, going either to that contact or to a newly created external handle. Commerce rarely
looks like that: a buyer pays a seller within a day or two of the first message. A long-distance
couple that met this summer does look like that, and pays the hold as the honest cost.

Two levels:
  * hold (24-hour cool-off and a call from the safety team) on the shape above, when the contact
    has had a real conversation with the payer (ten or more messages);
  * warn (an interstitial) on any other first payment to a payout handle the platform has only
    just started seeing. Newcomers moving money to their own new bank account pay that friction.
Scored in simulation: each scam payment carries a sealed "would a warning / a hold have stopped
it" flag, and stopping one payment stops the rest of that victim's chain.

    python solutions/round3_interventions.py     # writes out/reference/actions_r3.csv and scores it
"""
import _ref
import trailmates as tm

BOND_DAYS = 3         # the hop came from a contact at least this old: scams bond first, commerce does not
BOND_MSGS = 10        # ...and after a real conversation, not a one-line promo that said "text me"
NEW_HANDLE_DAYS = 120  # an external payout handle first seen recently


def decide(p):
    first = p["first_to_payee"]
    new_handle = p["payee_kind"] == "external" and p["payee_age_days"] <= NEW_HANDLE_DAYS
    bonded = p["offplatform_contact"] and p["offplatform_contact_days"] >= BOND_DAYS \
        and p["offplatform_contact_msgs"] >= BOND_MSGS
    if first and bonded and (p["payee_is_offplatform_contact"] or new_handle):
        return "hold"
    if first and new_handle:
        return "warn"
    return None


def detect(pays=None):
    out = {}
    for p in pays or tm.payments():
        a = decide(p)
        if a:
            out[p["payment_id"]] = a
    return out


if __name__ == "__main__":
    p = tm.write_actions(_ref.path("actions_r3.csv"), detect())
    _ref.score(["--actions", p])
