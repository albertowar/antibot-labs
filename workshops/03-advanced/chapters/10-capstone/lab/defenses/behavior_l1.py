"""
Chapter 5, Layer 1: presence & sanity (Section 5.3, Round 1).

Did a hand do this at all? Cheap rules about what is *missing*: pointer
travel before a click, keystrokes behind the text, time to read the page.

    rule                       points  why it fires
    no behavior telemetry      30      the reservation arrived without a collector record
    untrusted click            60      el.click() from page JS: isTrusted is false
    submitted too fast         40      form done in < 2 s from page load
    teleport click             20      mouse click with < 3 positions in the second before
    pixel-perfect centre       15      click within 1 px of the target's exact centre
    text without keystrokes    20      insertText with no keydown behind it
    starts at (0, 0)           10      first pointer sample at the page origin
    bulk fill                   5      paste / autofill / password manager (logged, ~harmless)

Not a rule, on purpose:
    - Keyboard activation (click with detail=0 and pointerType ""): keyboard
      and screen-reader users never move a mouse. "No mouse = bot" blocks them.
    - Touch taps: a finger has no hover path, so touch is exempt from teleport
      and from the centre rule here. Layer 5 looks at taps (Round 5).

False positives you should expect from this layer:
    - No telemetry at all: JavaScript disabled, a script blocker, a collector
      that failed to load. That is why it is worth a challenge (30), never a
      block: the no_js shopper pays a step-up, not a lost pair. A bot that skips
      the collector pays the same, so the rule only raises the floor.
    - Voice control (Dragon, Voice Access) warps the cursor to the target's
      centre and dictates text without keys: teleport + centre + text = 55,
      a challenge. Same score as an AI agent (Section 5.9). That is a real cost.
    - Password managers fill several fields with no keys: only 5 points here,
      because punishing autofill punishes the users with the best security habits.

CDP-driven browsers (Playwright, Puppeteer) produce isTrusted=true events,
so the untrusted-click rule only catches in-page JS automation, never Playwright.

Enabled for POST /drop/<sku> (action:drop_buy) when DEFENSE_LEVEL >= 1.
"""

from . import behavior
from .pipeline import Check

TOO_FAST_MS = 2000


def score_presence(features):
    """[(points, name, reason)] for one session's features (None = no telemetry)."""
    if features is None:
        return [(30, "no_telemetry", "No behavior telemetry: the collector never reported")]
    reasons = []
    clicks = features["clicks"]

    if any(not c["trusted"] for c in clicks):
        reasons.append((60, "untrusted_click", "Untrusted click event (isTrusted=false): clicked from page JS"))

    submit = features.get("submit_ms")
    if submit is not None and submit < TOO_FAST_MS:
        reasons.append((40, "too_fast", f"Form submitted {submit:.0f} ms after page load"))

    mouse_clicks = [c for c in clicks if c["mouse"]]
    teleports = [c for c in mouse_clicks if c["positions_1s"] < 3]
    if teleports:
        reasons.append((20, "teleport", f"Teleport click: {len(teleports)}/{len(mouse_clicks)} mouse clicks "
                                        "with no pointer travel before them"))

    centred = [c for c in mouse_clicks if c.get("center_offset") is not None and c["center_offset"] <= 1.0]
    if centred:
        reasons.append((15, "centre", f"{len(centred)} click(s) within 1 px of the target's exact centre"))

    injected = features["fills"]["injected_fields"]
    if injected:
        reasons.append((20, "text_without_keys", f"Text without keystrokes in {', '.join(injected)}"))

    if features.get("first_point") == [0, 0]:
        reasons.append((10, "origin_start", "First pointer sample at page origin (0, 0)"))

    bulk = features["fills"]["bulk_fields"]
    if bulk:
        reasons.append((5, "bulk_fill", f"Bulk fill (paste/autofill) in {', '.join(bulk)}"))

    return reasons


CHECK = Check("behavior_l1", lambda ctx: behavior.signals("l1", score_presence(behavior.features(ctx))),
              phases=("action:drop_buy",))


if __name__ == "__main__":
    import json
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    from defenses.behavior_features import extract
    trace = json.load(open(sys.argv[1]))
    for points, _, reason in score_presence(extract(trace["telemetry"], trace["layout"])):
        print(f"{points:>3}  {reason}")
