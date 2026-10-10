"""
The eight sensor layers (inherited from W2 Ch8)

Each module is a deliberately small stand-in for a defense you built (or
will build) in an earlier chapter. Each one exposes:

    LAYER     the layer name used in logs, veto thresholds and reports
    SIGNALS   {signal_name: what it means}
    sense(ctx) -> [signal_name, ...]

A sensor only *reports*. It never blocks. Deciding what to do with the
signals is the job of the decision engine (veto.py in Round 1, policy.py
from Round 2 on). Keeping detection and decision apart is the single most
useful architectural rule in this chapter: it is what lets you run a new
layer in shadow mode, re-weight it without a deploy, and replay old traffic
against a new policy (tools/sweep.py).
"""

from . import automation, behavior, fingerprint, headers, honeypot, net, tls, velocity

# Cheapest first: the order a production pipeline would run them in
BASE_SENSORS = [net, headers, tls, velocity, honeypot, automation, fingerprint, behavior]
