"""
Chapter 1: the sensor gate (Section 1.2, Round 1). Pre-written: read it, then finish the TODOs in
the layer modules.

From level 2 (Round 1; round N runs at level N+1), the product API and the cart (policy.SENSOR_GATED) need a sensor report for this
session. A client that never runs the page's JavaScript has none: raw HTTP scrapers, and real
people with JavaScript disabled or the script blocked.

    rule                    points  why
    no sensor report        40      no valid POST /api/telemetry {"kind": "sensor"} for this session

40 is a block in this lab's bands (defenses/policy.py). That is the price of a JavaScript gate:
the no-JS shopper is blocked from Round 1 on, and the checkpoint counts it as an accepted cost
(allowed_fp). A gate that blocks everyone without JavaScript is a product decision, not a detection.

What it does not stop: a client that skips the browser and posts a believable report itself
(Round 5, attacks/round5_forged_sensor.py). Binding the report to a challenge it cannot fake is
Chapter 4.
"""

from . import policy, sensor
from .pipeline import Check, Signal


def _check(ctx):
    if not sensor.gated(ctx) or sensor.report(ctx) is not None:
        return None
    ctx.note(sensor_reasons=["[gate] No sensor report for this session (JavaScript disabled, blocked or skipped)"])
    return [Signal("sensor_gate", "no_sensor", policy.NO_SENSOR_POINTS, "no sensor report for this session")]


CHECK = Check("sensor_gate", _check, phases=("request",))
