"""
Round 1 attack: the compromised vendor include skims the checkout and the login.

Scenario: a third-party analytics file your store hosts was swapped for one that also carries a
skimmer (think Polyfill.io, 2024). It listens for the form submit and sendBeacons the fields to the
attacker. With no policy in its way yet, nothing stops it.

Point of the round: your inventory and change monitor DETECT this (defenses/inventory_scripts.py,
defenses/script_monitor.py), but detection does not stop the exfil. Run this after you have seen the
CHANGED alert: the card still gets out.

Technique: variant "beacon". Beaten by: nothing in this round (that is the lesson).
    python attacks/round1_vendor_skimmer.py
"""
import _common

if __name__ == "__main__":
    _common.run("Round 1: vendor skimmer (sendBeacon)", "beacon")
