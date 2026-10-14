"""
The eight base sensor layers, run on every login (action:login).

Each `sensor_*.py` is a deliberately small stand-in for a defense you built (or will build) in
an earlier chapter. Each one exposes:

    LAYER     the layer name used in logs, veto lines and reports
    SIGNALS   {signal_name: what it means}
    sense(ctx) -> [signal_name, ...]

A sensor only *reports*. It never blocks: this check turns the names into Signals whose points
are policy.WEIGHTS, and policy.decide() picks the response (nothing at level 0, the veto chain at
level 1, the risk score and response ladder from level 2). Keeping detection and decision apart
is the single most useful architectural rule in this chapter: it is what lets you run a new layer
in shadow mode, re-weight it without a deploy, and replay old traffic against a new policy
(tools/sweep.py).

Everything the layers saw goes to the decision log in `extra.signals` ({layer: [names]}), also
when a signal weighs nothing and at level 0, where nothing is enforced.
"""

from . import (policy, sensor_automation, sensor_behavior, sensor_fingerprint, sensor_headers,
               sensor_honeypot, sensor_net, sensor_tls, sensor_velocity)
from .pipeline import Check, Signal

# Cheapest first: the order a production pipeline would run them in
BASE_SENSORS = [sensor_net, sensor_headers, sensor_tls, sensor_velocity, sensor_honeypot,
                sensor_automation, sensor_fingerprint, sensor_behavior]

LOGIN = ("action:login",)


def emit(ctx, layer, names):
    """Record what a layer saw (for the log and the sweep) and return it as Signals."""
    seen = ctx.attrs.setdefault("ch8_layers", {})
    if names:
        seen[layer] = list(names)
    ctx.note(signals=seen)
    return [Signal(layer, n, policy.WEIGHTS.get(n, 0)) for n in names]


def _check(ctx):
    out = []
    for module in BASE_SENSORS:
        out += emit(ctx, module.LAYER, module.sense(ctx))
    return out


CHECK = Check("sensors", _check, phases=LOGIN)
