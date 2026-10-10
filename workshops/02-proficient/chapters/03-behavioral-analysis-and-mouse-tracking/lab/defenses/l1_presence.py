"""
Chapter 3, Layer 1: presence & sanity (Section 3.3, Round 1).

Did a hand do this at all? Cheap rules about what is *missing*: pointer
travel before a click, keystrokes behind the text, time to read the page.

    rule                       points  why it fires
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
    - Touch taps: a finger has no hover path, so touch is exempt from teleport.

False positives you should expect from this layer:
    - Voice control (Dragon, Voice Access) warps the cursor to the target's
      centre and dictates text without keys: teleport + centre + text = 55,
      a challenge. Same score as an AI agent (Section 3.8). That is a real cost.
    - Password managers fill several fields with no keys: only 5 points here,
      because punishing autofill punishes the users with the best security habits.

CDP-driven browsers (Playwright, Puppeteer) produce isTrusted=true events,
so the first rule only catches in-page JS automation, never Playwright.
"""

TOO_FAST_MS = 2000


def score_presence(features):
    reasons = []
    clicks = features["clicks"]

    if any(not c["trusted"] for c in clicks):
        reasons.append((60, "Untrusted click event (isTrusted=false): clicked from page JS"))

    submit = features.get("submit_ms")
    if submit is not None and submit < TOO_FAST_MS:
        reasons.append((40, f"Form submitted {submit:.0f} ms after page load"))

    mouse_clicks = [c for c in clicks if c["mouse"]]
    teleports = [c for c in mouse_clicks if c["positions_1s"] < 3]
    if teleports:
        reasons.append((20, f"Teleport click: {len(teleports)}/{len(mouse_clicks)} mouse clicks "
                            "with no pointer travel before them"))

    centred = [c for c in mouse_clicks if c.get("center_offset") is not None and c["center_offset"] <= 1.0]
    if centred:
        reasons.append((15, f"{len(centred)} click(s) within 1 px of the target's exact centre"))

    injected = features["fills"]["injected_fields"]
    if injected:
        reasons.append((20, f"Text without keystrokes in {', '.join(injected)}"))

    if features.get("first_point") == [0, 0]:
        reasons.append((10, "First pointer sample at page origin (0, 0)"))

    bulk = features["fills"]["bulk_fields"]
    if bulk:
        reasons.append((5, f"Bulk fill (paste/autofill) in {', '.join(bulk)}"))

    return reasons


if __name__ == "__main__":
    import json
    import sys
    from features import extract
    trace = json.load(open(sys.argv[1]))
    for points, reason in score_presence(extract(trace["telemetry"], trace["layout"])):
        print(f"{points:>3}  {reason}")
