"""
W3 Ch2 ext: the live drop feed, a WebSocket at /ws/drop (flask-sock, on the store's own port).

    subscribe              -> {"event": "inventory", "sku": "lab-runner-9", "left": N}
    {"action": "bid", ...} -> {"event": "bid_ack", "item": ...}        (a state-changing message: needs auth)

How the gate sees a WebSocket (no contract change needed, and worth knowing before you defend one):

  * The HANDSHAKE is an ordinary GET. It goes through ``gate.before_request`` like any page, with phase
    ``request``: a check that refuses it (a 403 before the upgrade) stops the connection from ever opening.
    That is where the Origin check lives (defenses/ws_guard.py).
  * After the upgrade there are no more HTTP requests, so the gate would never run again. This module runs the
    ladder itself, once per FRAME, in the phase ``ws:message`` (``gate.run_phase``), with the per-connection
    state in ``ctx.attrs["ws"]``. The checks that apply to ``ws:*`` decide; this module only carries the answer
    out as a WebSocket frame (an error frame, or a close), because ``gate.respond`` builds HTTP responses.
  * The decision log gets ONE row for the whole connection (written when the socket closes): its ``outcome``
    is what the connection experienced, its ``extra`` carries the frame counts, and its ``ms`` is the gate cost
    of an average frame. That is what an HTTP-only limiter never sees: a flood is one request.

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import json
import time

from flask import g
from flask_sock import Sock

from demo_site import gate
from demo_site.models import Product

DROP_SKU = "lab-runner-9"
IDLE_TIMEOUT = 10        # seconds without a frame before the server hangs up


def _send(ws, **payload):
    ws.send(json.dumps(payload))


def feed(ws):
    ctx = g.ctx
    bearer = ctx.attrs.get("bearer")
    state = {"subject": bearer["sub"] if bearer else None, "origin": ctx.header("Origin"), "close": False,
             "msg": None, "frames": 0, "accepted": 0, "rejected": 0}
    ctx.attrs["ws"] = state
    gate_ms = 0.0
    while not state["close"]:
        raw = ws.receive(timeout=IDLE_TIMEOUT)
        if raw is None:
            break
        try:
            msg = json.loads(raw)
        except ValueError:
            msg = None
        if not isinstance(msg, dict):
            _send(ws, error="frames must be JSON objects")
            continue
        state["msg"], state["frames"] = msg, state["frames"] + 1
        before = g.gate_ms
        d = gate.run_phase("ws:message", ctx)
        gate_ms += g.gate_ms - before
        # one worst-case decision per connection in the log, not one per frame
        g.decisions[:] = [max(g.decisions, key=lambda x: (x.action not in ("allow", "monitor"), x.score))]
        if d.action not in ("allow", "monitor"):
            state["rejected"] += 1
            g.outcome = "rate_limited" if d.action == "rate_limit" else "blocked"
            _send(ws, error=state.get("reason") or "refused", code=4029 if d.action == "rate_limit" else 4401)
            continue
        state["accepted"] += 1
        action = msg.get("action")
        if action == "subscribe":
            p = Product.query.filter_by(sku=DROP_SKU).first()
            _send(ws, event="inventory", sku=DROP_SKU, left=p.stock if p else 0)
        elif action == "bid":
            _send(ws, event="bid_ack", item=msg.get("item_id"))
        else:
            _send(ws, event="ok")
    if state["close"]:
        g.outcome = "blocked"
        ws.close()
    frames = max(1, state["frames"])
    g.gate_ms = g.gate_ms - gate_ms + gate_ms / frames        # the row's ms: the average gate cost of one frame
    ctx.note(ws_frames=state["frames"], ws_accepted=state["accepted"], ws_rejected=state["rejected"],
             ws_gate_ms_total=round(gate_ms, 2), ws_closed_by_server=state["close"])


def init(app):
    sock = Sock(app)
    sock.route("/ws/drop")(feed)
