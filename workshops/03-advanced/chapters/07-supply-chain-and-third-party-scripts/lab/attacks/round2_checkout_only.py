"""
Round 2 attack: wake only on the payment and login pages, and exfil from an injected script.

Beating Round 1's defense: a one-shot crawl of the home page never saw the skimmer, because it only
arms itself on /checkout and /login and runs its exfil from a dynamically injected <script>. It still
needs fetch or sendBeacon to reach the attacker's origin.

Point of the round: a CSP with connect-src 'self' stops that cross-origin call. The injected script
may run; the data has nowhere to go. Report-Only shows you what enforcement would break first.

Technique: variant "dynamic". Beaten by: CSP enforce (level 2).
    python attacks/round2_checkout_only.py                 # against whatever the store enforces
    python attacks/round2_checkout_only.py --report-only   # the store sends the CSP as Report-Only
"""
import sys

import _common

if __name__ == "__main__":
    ro = "--report-only" in sys.argv
    _common.run("Round 2: checkout-only dynamic skimmer" + (" (CSP Report-Only)" if ro else ""), "dynamic", report_only=ro)
