"""
Round 2 attack — wake only on checkout, exfil from an injected script.

Beating Round 1's defence: a one-shot crawl of the homepage never saw the
skimmer, because it only arms itself on /checkout and runs the exfil from a
dynamically injected <script>. It still uses fetch/sendBeacon to reach the
attacker's origin.

Point of the round: a CSP with connect-src 'self' (even report-only promoted
to enforce) blocks that cross-origin fetch/beacon. The injected script may run,
but the data has nowhere to go.

Expects server: SKIMMER_VARIANT=dynamic; beaten by CSP_MODE=enforce
Run:
    python attacks/round2_checkout_only.py
"""
import _common

def run(base=_common.BASE):
    return _common.run(base)

if __name__ == "__main__":
    raise SystemExit(_common.report("Round 2: checkout-only dynamic skimmer"))
