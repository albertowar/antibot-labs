"""
drop_guard: the capstone's glue. It points the chapters' sensor checks at the drop.

Chapter 1 built its checks for the surface it taught: the sensor gate and the three layers that read the
sensor report (automation_artifacts, consistency, lie_detection) run on every request and judge the
GATED paths (policy.SENSOR_GATED) in the "request" phase. The capstone needs the same judgment on the
moment of the buy, so it does not copy and edit those modules (copies drift). It re-wraps them:

    at_drop(check)    the same function, the same name, the phase action:drop_buy

`POST /drop/<sku>` and `POST /api/buy` enter that phase just before the irreversible step
(demo_site/routes/pages.py, api.py: `guard("drop_buy")`). Two reasons not to leave them in the request
phase: the drop PAGE is where the sensor runs (a gate on the page would refuse the page that produces
the report it asks for), and the buy is the only request whose cost to the defender is worth paying.

That phase decides on ITS OWN signals: the request phase already ran for this POST (headers, TLS), but
its points do not carry over. Chapter 3's behavior layers are already written for this phase.

Trade-off: judging only at the buy means a scraper that never buys is not judged by the sensor at all.
That is the right trade for a drop (nothing else is scarce) and the wrong one for a catalogue (W2 Ch1
gates the product API for that reason).
"""

from .pipeline import Check

DROP = ("action:drop_buy",)


def at_drop(check):
    """The same check, run at the buy instead of on every request."""
    return Check(check.name, check.fn, phases=DROP)


if __name__ == "__main__":
    from . import sensor_gate
    c = at_drop(sensor_gate.CHECK)
    print(f"{c.name:<16} phases={c.phases}")
