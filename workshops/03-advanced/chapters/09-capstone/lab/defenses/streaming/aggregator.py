"""
Capstone L6 — fold the streaming verdict back into the risk engine (W3 Ch3)

A production stack runs the stream processors out of band (Faust/Redpanda) and
writes a per-session verdict that the request path reads cheaply. We do the
same: observe() writes stream:pts:<sid>; score_stream() reads it. The read is a
single Redis GET on the hot path, which is the point — the expensive windowing
happened in the stream, not in the request.
"""

import json


def score_stream(store, sid):
    if not sid:
        return 0, []
    points = int(store.get(f"stream:pts:{sid}") or 0)
    why = store.get(f"stream:why:{sid}")
    reasons = json.loads(why) if why else []
    return min(points, 100), reasons
