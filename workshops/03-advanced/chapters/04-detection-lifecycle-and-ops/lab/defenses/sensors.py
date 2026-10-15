"""
The eight base sensor layers, run on every login (action:login).

Each `sensor_*.py` is a deliberately small stand-in for a defense you built in an earlier chapter
(this chapter does not build them again; it operates them). Each one exposes:

    LAYER     the layer name used in logs and reports
    SIGNALS   {signal_name: what it means}
    sense(ctx) -> [signal_name, ...]

A sensor only *reports*. It never blocks: this check turns the names into Signals whose points are
the policy weights *as the operator has them set right now* (defenses/ops.py), and policy.decide()
picks the response. Keeping detection and decision apart is the single most useful architectural
rule in this stack: it is what lets you run a new layer in shadow mode, re-weight it without a
deploy, and replay old traffic against a new policy (tools/sweep.py).

Everything the layers saw goes to the decision log in `extra.signals` ({layer: [names]}), also when
a signal weighs nothing, together with the numbers the operations tools need later: the telemetry
summary (`tel`), the network kind (`edge_type`) and the campaign cluster key (`cluster`).
"""

from . import (features, netinfo, ops, sensor_automation, sensor_behavior, sensor_fingerprint,
               sensor_headers, sensor_honeypot, sensor_net, sensor_tls, sensor_velocity)
from .pipeline import Check, Signal

# Cheapest first: the order a production pipeline would run them in
BASE_SENSORS = [sensor_net, sensor_headers, sensor_tls, sensor_velocity, sensor_honeypot,
                sensor_automation, sensor_fingerprint, sensor_behavior]

LOGIN = ("action:login",)


def emit(ctx, layer, names):
    """Record what a layer saw (for the log, the health tools and the model) and return it as
    Signals scored with the operator's current weights."""
    seen = ctx.attrs.setdefault("ops_layers", {})
    if names:
        seen[layer] = list(names)
    ctx.note(signals=seen)
    weights = ops.state(ctx)["weights"]
    return [Signal(layer, n, weights.get(n, 0)) for n in names]


def flat(ctx):
    """Every signal name the layers reported so far on this request."""
    return [n for names in ctx.attrs.get("ops_layers", {}).values() for n in names]


def _check(ctx):
    out = []
    for module in BASE_SENSORS:
        out += emit(ctx, module.LAYER, module.sense(ctx))
    t = features.of(ctx)
    ctx.note(tel=features.numbers(t), edge_type=netinfo.of(ctx)["kind"], cluster=features.cluster_key(ctx))
    return out


CHECK = Check("sensors", _check, phases=LOGIN)
