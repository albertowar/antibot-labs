"""
Round 1 attack — the compromised vendor include skims the checkout.

Scenario: a third-party analytics file your store hosts was swapped for one
that also carries a skimmer (think Polyfill.io, 2024). It listens for the
checkout submit and sendBeacons the fields straight to the attacker. With no
CSP yet, nothing is in its way.

Point of the round: your inventory + change-monitor will DETECT this, but
detection does not stop the exfil. Run this after building the baseline and
seeing the CHANGED alert — the card still gets out.

Expects server: SKIMMER_VARIANT=beacon, CSP_MODE=off
Run (demo store + collector must be up):
    python attacks/round1_vendor_skimmer.py
"""
import _common

def run(base=_common.BASE):
    return _common.run(base)

if __name__ == "__main__":
    raise SystemExit(_common.report("Round 1: vendor skimmer (sendBeacon)"))
