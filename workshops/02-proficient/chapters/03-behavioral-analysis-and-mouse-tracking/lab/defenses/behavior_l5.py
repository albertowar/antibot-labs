"""
Chapter 3, Layer 5: touch realism (Section 3.7, Round 5).

Layers 1-4 exempt touch on purpose. A finger has no hover path, so there is
nothing for the teleport and path rules to look at, and a phone's virtual
keyboard reports key "Unidentified" with ~0 ms holds, so the keystroke rules
skip it too. The Round 5 bot uses exactly those exemptions: a Playwright
context with touch emulation, page.tap() on every field, and IME-style keys
sent over the DevTools Protocol. Before this layer it scores 0.

What a scripted tap still gets wrong:

    rule                        points  why it fires
    instant taps                35      >= 2 taps whose contact (pointerdown -> pointerup)
                                        lasted < 15 ms; human taps last ~40-150 ms
    dead-centre taps            30      >= 2 taps within 1 px of the target's exact centre;
                                        fingers land off centre (and usually low)

Both together make 65, a block. Either alone is a challenge.

False positives you should expect:
    - Very fast tappers rarely get under 15 ms on two taps in one form; switch
      access and some assistive tech (Section 3.9) can. That is why one rule
      alone is a challenge, not a block.
    - A stylus on a tablet reports pointerType "pen", not "touch", so it goes
      through the mouse rules instead.

What this layer does NOT score yet: the contact geometry (width, height,
pressure) the collector now logs with each pointerdown. Android and iOS
report it differently and the lab has no real-phone capture to calibrate
against, so it is shown in the viewer and kept out of the score. The attacker
answer to this layer (Input.dispatchTouchEvent with a random hold, an
off-centre point and a finger-sized radius, attacks/round5_touch_tap.py --cdp)
fixes both rules for the price of one more line each. Touch carries far less
behavioral signal than a mouse; phone traffic leans on device coherence
(W2 Ch4), the network stack (W2 Ch5) and reputation.

Enabled for POST /drop/<sku> (action:drop_buy) when DEFENSE_LEVEL >= 5.
"""

from . import behavior
from .pipeline import Check

INSTANT_TAP_MS = 15
CENTRE_PX = 1.0
MIN_TAPS = 2


def score_touch(features):
    """[(points, name, reason)] for one session's touch taps."""
    if features is None:
        return []
    taps = [c for c in features["clicks"] if c["kind"] == "t" and c["trusted"]]
    reasons = []
    instant = [c for c in taps if c.get("hold_ms") is not None and c["hold_ms"] < INSTANT_TAP_MS]
    if len(instant) >= MIN_TAPS:
        reasons.append((35, "instant_taps", f"{len(instant)}/{len(taps)} taps with < {INSTANT_TAP_MS} ms of contact "
                                            f"(shortest {min(c['hold_ms'] for c in instant):.0f} ms)"))
    centred = [c for c in taps if c.get("center_offset") is not None and c["center_offset"] <= CENTRE_PX]
    if len(centred) >= MIN_TAPS:
        reasons.append((30, "centre_taps", f"{len(centred)}/{len(taps)} taps within {CENTRE_PX:.0f} px of the "
                                           "target's exact centre"))
    return reasons


CHECK = Check("behavior_l5", lambda ctx: behavior.signals("l5", score_touch(behavior.features(ctx))),
              phases=("action:drop_buy",))
