"""
Level 6: fold the streaming verdict into the request path (W3 Ch3).

A production stack runs the stream processors out of band (Faust, Kafka Streams, Flink) and writes a per-session
verdict that the request path reads cheaply. The capstone does the same: stream_detectors.observe() writes
lab:stream:sig:<sid>; this check reads it. The read is one HGETALL on the hot path, which is the point: the
expensive windowing happened in the stream, not in the request.

It runs in the `request` phase, on every gated request of the session. Points land in the challenge band alone
(55 against a 30 to 59 band): a script that cannot run the "proof" challenge stops there, a person on a flagged
session solves it and carries on. Two layers firing together (a burst that is also machine-even) reach a block.

False positives: the rate detector is per session, never per address, because a carrier NAT or an office puts
hundreds of customers behind one IP (W1 Ch2). The regularity detector flags legitimate machine clients, a status
poller or a price-sync job, that are *supposed* to be regular: allowlist them by token or path, not by raising the
threshold until they pass. The checkpoint shows the people it must not touch.
"""

from . import stream_detectors
from .pipeline import Check, Signal


def _check(ctx):
    found = stream_detectors.verdict(ctx.redis, ctx.session.sid)
    if not found:
        return None
    return [Signal("streaming", name, int(v["points"]), v["reason"]) for name, v in sorted(found.items())]


CHECK = Check("streaming", _check, phases=("request",))
