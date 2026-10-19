"""
W2 Ch1 — Defense Layer 4: Interaction Evidence (Section 1.4)

A driver-level stealth tool (patchright) leaves the JavaScript environment
honest: nothing to catch in Layers 1-3. What it still does is drive the page
through the DevTools Protocol, and Playwright's page.click() has a
signature:

  - it dispatches one or two pointer moves straight to the target, then the
    press and release (no path, no hover before it), and
  - it aims at the exact centre of the element's bounding box.

The events are isTrusted=true (they come from the browser's input pipeline),
so the old "isTrusted" check only catches bots that call element.click()
from JavaScript. We keep it because it is free.

This layer only protects ACTIONS (Add to cart). Scraping /api/products
needs no click, so it stays open at Level 4: see the debrief.

False positives, and why the rules are shaped like this:
  - Keyboard and assistive-technology users activate buttons with
    Enter/Space: detail == 0, no pointer movement at all. They are accepted
    without further checks. Blocking them would be an accessibility failure.
  - Touch users tap without hovering: no pointermove before the click is
    normal, so the movement rule only applies to mouse/pen input.
  - One rule alone is worth 25 ("suspicious"). Only "teleported AND dead
    centre" (or an untrusted event) reaches 40.

This is the shallow end of behavioural detection; Chapter 5
builds the real thing (trajectories, timing, keystroke dynamics).

Enabled for POST /api/cart/add (phase action:cart_add) when DEFENSE_LEVEL >= 5 (Round 4; round N runs at level N+1). The page sends the
click evidence in the request body ({"sku": ..., "interaction": {...}}). Try it on its own:
    python -m defenses.interaction
"""

MIN_POINTER_MOVES = 3        # Playwright's page.click() produces 1-2
CENTRE_TOLERANCE_PX = 1.0       # Playwright aims at the centre, rounded to the pixel grid


def check_teleport(interaction):
    """
    Round 4: a mouse user moves the pointer to a button before clicking it.
    Returns (points, reasons).
    """
    moves = interaction.get("moves_before", 0)
    if moves < MIN_POINTER_MOVES:
        return 25, [f"Pointer teleported: only {moves} pointermove event(s) before the click"]
    return 0, []


def check_dead_centre(interaction):
    """Humans almost never land within a pixel of the exact centre of a button."""
    if (abs(interaction.get("offset_x", 99)) <= CENTRE_TOLERANCE_PX
            and abs(interaction.get("offset_y", 99)) <= CENTRE_TOLERANCE_PX):
        return 25, ["Click landed within 1px of the exact centre of the button"]
    return 0, []


def score_interaction(interaction, signals):
    """Layer 4. `signals` is the session's sensor payload. Returns (score, reasons)."""
    if not interaction:
        return 40, ["No interaction evidence for this action (API called directly)"]
    if interaction.get("is_trusted") is False:
        return 60, ["Synthetic click (isTrusted=false): dispatched by page JavaScript"]
    if interaction.get("detail") == 0:
        return 0, []                        # keyboard / assistive technology: accepted
    score = 0
    reasons = []
    pointer = interaction.get("pointer_type") or "mouse"
    if pointer == "touch":
        if (signals or {}).get("max_touch_points") == 0:
            score += 30
            reasons.append("Touch input on a device that reports no touch support")
    else:
        points, why = check_teleport(interaction)
        score += points
        reasons.extend(why)
    points, why = check_dead_centre(interaction)
    score += points
    reasons.extend(why)
    return score, reasons


# Wiring (no need to edit): runs when the cart route asks the gate about the action.
from . import sensor  # noqa: E402
from .pipeline import Check  # noqa: E402


def _check(ctx):
    interaction = (ctx.json or {}).get("interaction") if isinstance(ctx.json, dict) else None
    points, reasons = score_interaction(interaction, sensor.report(ctx))
    return sensor.signals("interaction", points, reasons, ctx)


CHECK = Check("interaction", _check, phases=("action:cart_add",))


if __name__ == '__main__':
    samples = {
        "Playwright page.click()": {"is_trusted": True, "pointer_type": "mouse", "detail": 1,
                                    "offset_x": 0, "offset_y": 0, "moves_before": 1},
        "Human with a mouse": {"is_trusted": True, "pointer_type": "mouse", "detail": 1,
                               "offset_x": -17.4, "offset_y": 3.2, "moves_before": 86},
        "Keyboard user (Enter)": {"is_trusted": True, "pointer_type": "", "detail": 0,
                                  "offset_x": -60, "offset_y": -20, "moves_before": 0},
        "button.click() from JS": {"is_trusted": False, "pointer_type": "", "detail": 0,
                                   "offset_x": 0, "offset_y": 0, "moves_before": 0},
    }
    for label, interaction in samples.items():
        print(f"{label:<26}", score_interaction(interaction, {"max_touch_points": 0}))
