"""
Capstone feature module: the stream (W3 Ch3). It publishes every gated request to the streaming layer and keeps one
lab route. Nothing here decides anything (defenses/stream_layer.py decides).

    after_request      for each gated request: {sid, ts_ms, path, method} -> defenses/stream_bus.publish(). In the
                       default `inproc` backend that runs the three detectors (defenses/stream_detectors.py) inline,
                       and the time it takes is added to the request's gate time, because inline detection is the
                       defender's cost. With STREAM_BACKEND=kafka the event goes to Redpanda and a consumer thread
                       started here runs the same detectors out of band (docker compose --profile prod).
    GET /lab/stream/me what the stream has concluded about YOUR session: the detectors that fired, the current CV
    GET /lab/stream/all the same for every session (tools/signalhealth.py)

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import importlib
import threading
import time

from flask import Blueprint, current_app, g, jsonify, request

from demo_site import hooks

bp = Blueprint("stream9", __name__)


def _defense(name):
    return importlib.import_module(f"defenses.{name}")


def _publish(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None:                                         # an ungated path (static files, /lab/*, the WebSocket)
        return response
    cfg = current_app.config["LAB"]
    if cfg.defense_level < 6 and not cfg.lab_shadow:        # below the layer, and not watching in shadow: no stream, no cost
        return response
    t0 = time.perf_counter()
    try:
        _defense("stream_bus").publish(current_app.extensions["lab_redis"],
                                       {"sid": ctx.session.sid, "ts_ms": int(time.time() * 1000),
                                        "path": request.path, "method": request.method})
    except Exception:
        pass                                                # the stream must never break the response
    if _defense("stream_bus").BACKEND != "kafka":
        g.gate_ms = getattr(g, "gate_ms", 0.0) + (time.perf_counter() - t0) * 1000
    return response


@bp.get("/lab/stream/me")
def me():
    """The streaming layer's view of this session (cookie `sid`), for the debrief and the attacks' printouts."""
    from demo_site import gate
    sid = gate.build_ctx(current_app).session.sid
    redis = current_app.extensions["lab_redis"]
    detectors = _defense("stream_detectors")
    return jsonify(sid=sid, fired=detectors.verdict(redis, sid), cv=detectors.cv_for(redis, sid),
                   backend=_defense("stream_bus").BACKEND)


@bp.get("/lab/stream/all")
def everyone():
    """Every session the stream has seen: gaps counted, CV, detectors fired (tools/signalhealth.py joins it with the log)."""
    redis = current_app.extensions["lab_redis"]
    detectors = _defense("stream_detectors")
    out = []
    for key in redis.scan_iter("lab:stream:welf:*", count=1000):
        sid = key.rsplit(":", 1)[1]
        out.append({"sid": sid, "gaps": int(redis.hget(key, "n") or 0), "cv": detectors.cv_for(redis, sid),
                    "fired": sorted(detectors.verdict(redis, sid))})
    return jsonify(sessions=out)


def init(app):
    app.register_blueprint(bp)
    app.after_request(_publish)
    bus = _defense("stream_bus")
    if bus.BACKEND == "kafka":
        threading.Thread(target=bus.run_consumer, args=(app.extensions["lab_redis"],), daemon=True).start()
