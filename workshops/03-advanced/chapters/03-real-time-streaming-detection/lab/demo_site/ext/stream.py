"""
Chapter 3's extension: the event log, the consumer thread and the lab's streaming routes.

    after every gated response   XADD one event to the Redis Stream (lab:stream:events), from a
                                 hooks.on_response observer (contract 1.7)
    a consumer thread            XREADGROUP -> defenses/consumer.py -> flags (the ladder's detectors)
    GET  /lab/stream/status      backlog (pending + lag), consumers, events/s, the detectors live now
    GET  /lab/stream/verdicts    the flags raised, with how late each one was (lag_ms)
    POST /lab/stream/consumer    {"delay_ms": 40, "consumers": 2}: the backpressure knob

Why on_response and not an enricher: enrichers run before the route, and what a detector needs
most (did this login FAIL?) is only known once the route has answered. The event is built from
the request's Ctx (edge IP, session, submitted account) and the note the login route already
leaves (`ctx.notes["login"]`). It never reads the ground-truth actor. The gate runs on_response
hooks just before it stamps the response and counts their time as gate cost, so the emit is
ordered deterministically and the defender pays for it on the scoreboard.

Ungated paths (/static, /img, /lab) build no Ctx; the observer skips them, so they never reach
the stream (the lab reads "looks human" from page views, not asset fetches).
"""

import json
import threading
import time

from flask import Blueprint, current_app, g, jsonify, request

from defenses import consumer, streamlog
from demo_site import hooks

CTRL = {"delay_ms": 0.0, "processed": 0, "busy_s": 0.0}
_threads = []                      # [(name, stop_event, thread)]
_lock = threading.Lock()
PAGE_PREFIXES = ("/api/", "/lab/", "/static/", "/img/")

bp = Blueprint("stream", __name__, url_prefix="/lab/stream")


def _event(ctx, response):
    p = request.path
    return {
        "ts": f"{time.time():.4f}", "sid": ctx.session.sid, "ip": ctx.ip, "path": p, "method": request.method,
        "status": response.status_code, "user": streamlog.submitted_email(ctx),
        "page": "1" if request.method == "GET" and response.status_code == 200 and not p.startswith(PAGE_PREFIXES) else "0",
        "login_failed": "1" if ctx.notes.get("login") == "fail" else "0",
        "bought": "1" if getattr(g, "purchased", False) else "0",
    }


def _observe(info):
    """hooks.on_response: one event per gated response. `emit_ms` stays a note (the checkpoint
    reads it); the gate adds the hook's time to the Server-Timing `gate` figure itself."""
    ctx = info.ctx
    if ctx is None:                # ungated path: no Ctx, no event
        return
    t0 = time.perf_counter()
    try:
        streamlog.emit(current_app.extensions["lab_redis"], _event(ctx, info.response))
    except Exception as exc:       # the log must never take the store down
        ctx.note(emit_error=repr(exc))
    ctx.note(emit_ms=round((time.perf_counter() - t0) * 1000, 3))


def _worker(app, name, stop):
    r = app.extensions["lab_redis"]
    streamlog.ensure_group(r)
    while not stop.is_set():
        t0 = time.perf_counter()
        try:
            n = consumer.step(r, name, app.config["LAB"].defense_level, app.config["LAB"].lab_reload,
                              delay_s=CTRL["delay_ms"] / 1000.0, counter=CTRL)
        except Exception as exc:
            print(f"[stream] {name}: {exc!r}")
            n = 0
        if n:
            CTRL["busy_s"] += time.perf_counter() - t0
        else:
            time.sleep(0.005)


def _set_consumers(app, n):
    with _lock:
        while len(_threads) < n:
            name = f"c{len(_threads) + 1}"
            stop = threading.Event()
            t = threading.Thread(target=_worker, args=(app, name, stop), daemon=True, name=f"stream-{name}")
            t.start()
            _threads.append((name, stop, t))
        while len(_threads) > n:
            _name, stop, _t = _threads.pop()
            stop.set()


@bp.route("/status")
def status():
    r = current_app.extensions["lab_redis"]
    pending, lag = streamlog.backlog(r)
    cfg = current_app.config["LAB"]
    live = [n for n, _m in consumer.enabled(cfg.defense_level, cfg.lab_reload)]
    busy = CTRL["busy_s"]
    return jsonify(level=cfg.defense_level, events=r.xlen(streamlog.EVENTS), pending=pending, lag=lag,
                   backlog=pending + lag, consumers=len(_threads), delay_ms=CTRL["delay_ms"],
                   processed=CTRL["processed"], events_per_s=round(CTRL["processed"] / busy, 1) if busy else 0.0,
                   detectors=live, flags=sum(1 for _ in r.scan_iter(streamlog.PREFIX + "flag:*")))


@bp.route("/verdicts")
def verdicts():
    r = current_app.extensions["lab_redis"]
    limit = min(2000, request.args.get("limit", 500, type=int))
    rows = [json.loads(f["json"]) for _id, f in r.xrange(streamlog.VERDICTS, count=limit)]
    return jsonify(items=rows, total=r.xlen(streamlog.VERDICTS))


@bp.route("/consumer", methods=["POST"])
def tune():
    body = request.get_json(silent=True) or {}
    if "delay_ms" in body:
        CTRL["delay_ms"] = max(0.0, float(body["delay_ms"]))
    if "consumers" in body:
        _set_consumers(current_app._get_current_object(), max(1, min(8, int(body["consumers"]))))
    return jsonify(ok=True, delay_ms=CTRL["delay_ms"], consumers=len(_threads))


def init(app):
    hooks.ungate("/lab/stream")
    app.register_blueprint(bp)
    hooks.on_response(_observe)
    CTRL.update(delay_ms=0.0, processed=0, busy_s=0.0)
    _set_consumers(app, 0)             # a second create_app() in one process retires the old workers
    _set_consumers(app, 1)
