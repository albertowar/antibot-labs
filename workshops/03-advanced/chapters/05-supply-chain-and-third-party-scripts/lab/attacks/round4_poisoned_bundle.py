"""
Round 4 attack — ship the skim inside a first-party bundle.

Beating Round 3's defence: the attacker stops touching the vendor file. A
poisoned build-time dependency (think the Shai-Hulud npm worm, Sept 2025) lands
the skim INSIDE your own first-party bundle. It ships from your origin, so SRI
matches your own build and the strict CSP nonces it like any of your code.
Neither control fires.

Point of the round: the runtime monitor wraps fetch/XHR/sendBeacon and reports
— and blocks — the call to a foreign origin even when it comes from first-party
code. Defence in depth for the gap CSP and SRI cannot see.

Expects server: SKIMMER_VARIANT=firstparty; beaten by MONITOR=on (with strict CSP)
Run:
    python attacks/round4_poisoned_bundle.py
"""
import _common

def run(base=_common.BASE):
    return _common.run(base)

if __name__ == "__main__":
    raise SystemExit(_common.report("Round 4: poisoned first-party bundle"))
