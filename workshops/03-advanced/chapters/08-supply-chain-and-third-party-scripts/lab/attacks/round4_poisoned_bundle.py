"""
Round 4 attack: ship the skim inside the first-party bundle.

Beating Round 3's defense: the attacker stops touching the vendor file. A poisoned build-time
dependency lands the skim INSIDE your own first-party bundle. It ships from your origin, so SRI
matches your own build and the strict CSP nonces it like any of your code, and its beacon rides the
one analytics origin connect-src must allow. Neither control fires.

Point of the round: the runtime monitor wraps fetch, XMLHttpRequest and sendBeacon and reports (and,
for sendBeacon, blocks) the call to a foreign origin even when it comes from first-party code.

Technique: variant "firstparty". Beaten by: the runtime monitor (level 4).
    python attacks/round4_poisoned_bundle.py
"""
import _common

if __name__ == "__main__":
    _common.run("Round 4: poisoned first-party bundle", "firstparty")
