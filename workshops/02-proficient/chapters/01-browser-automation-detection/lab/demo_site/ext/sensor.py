"""
Chapter 1 extension: the bot sensor on every page of the store.

What it adds (no starter file is edited):

    body_end slot          sensor/script.html loads static/js/sensor.js with a one-time nonce and
                           posts the report as soon as the page loads
    home.html override     ext/templates/home.html adds a "Quick add" panel that, like the old lab's
                           store page, waits for the sensor, then loads /api/products and offers
                           Add to cart buttons that call /api/cart/add with the click evidence
    telemetry "sensor"     POST /api/telemetry {"kind": "sensor", "nonce": ..., "signals": {...}}:
                           the nonce must be this session's, unused and fresh; then the signals become
                           the session's sensor report (defenses/sensor.py)
    /lab/sensor/check      how the server scores this session's report, layer by layer (the old /sensor-check)
    /lab/sensor/logs       the last 50 gated requests with their sensor reasons (the old /sensor-logs)
    /lab/capture           save YOUR browser as a real-user profile (tools/profiles/captured-<name>.json)

The /lab/ routes are lab pages: never gated, loopback only. In production never tell a client
which rule caught it; the sensor itself never learns its verdict.
"""

import json
import os
import re
import secrets
import time
from datetime import date

from flask import Blueprint, current_app, g, jsonify, render_template, request

from demo_site import hooks

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROFILES_DIR = os.path.join(LAB, "tools", "profiles")
NONCE, NONCE_AT = "sensor_nonce", "sensor_nonce_at"

bp = Blueprint("lab_sensor", __name__, url_prefix="/lab")


def _defenses():
    from defenses import policy, sensor     # through the modules: defenses/ is hot-reloaded
    return policy, sensor


def _nonce():
    """Called by sensor/script.html on every page view: a fresh one-time nonce for this session."""
    ctx = getattr(g, "ctx", None)
    if ctx is None:
        return ""
    nonce = secrets.token_urlsafe(18)
    ctx.session.set(NONCE, nonce)
    ctx.session.set(NONCE_AT, f"{time.time()}")
    return nonce


def _on_sensor(ctx, payload):
    """Keep the report only if it carries this session's fresh, unused nonce (single use)."""
    policy, sensor = _defenses()
    nonce, issued = ctx.session.get(NONCE), float(ctx.session.get(NONCE_AT) or 0)
    if not nonce or payload.get("nonce") != nonce or time.time() - issued > policy.NONCE_TTL:
        return {"stored": False}
    ctx.session.delete(NONCE)
    sensor.store_report(ctx, payload.get("signals") or {})
    return {"stored": True}


@bp.route("/sensor/check")
def check():
    """How the server scores this session's sensor report at every level (debug, never gated)."""
    from demo_site import gate
    from defenses import automation_artifacts, consistency, interaction, lie_detection
    policy, sensor = _defenses()
    ctx = gate.build_ctx(current_app)
    signals = sensor.report(ctx)
    layers = []
    if signals is not None:
        for level, name, fn in ((1, "automation_artifacts", lambda: automation_artifacts.score_automation_artifacts(signals)),
                                (2, "consistency", lambda: consistency.score_consistency(signals, sensor.headers(ctx))),
                                (3, "lie_detection", lambda: lie_detection.score_lies(signals))):
            points, reasons = fn()
            layers.append({"level": level, "layer": name, "points": points, "reasons": reasons})
    level = current_app.config["LAB"].defense_level
    score = sum(x["points"] for x in layers if x["level"] <= level)
    return jsonify(level=level, report=signals is not None, score=score if signals is not None else None,
                   verdict=None if signals is None else policy.decide(min(100, score), [], level), layers=layers,
                   note="interaction evidence (level 4) is scored per click, on POST /api/cart/add")


@bp.route("/sensor/logs")
def logs():
    """The last N requests to the gated paths, with what the sensor checks said."""
    from demo_site.models import Decision
    policy, _ = _defenses()
    current_app.extensions["decision_log"].flush()
    n = min(500, request.args.get("limit", 50, type=int))
    rows = (Decision.query.filter(Decision.path.in_(policy.SENSOR_GATED)).order_by(Decision.id.desc()).limit(n).all())
    return jsonify([{"ts": d.ts.isoformat() + "Z", "sid": (d.sid or "")[:6], "level": d.level, "path": d.path,
                     "status": d.status, "score": d.score, "action": d.action, "signals": d.signals,
                     "reasons": (d.extra or {}).get("sensor_reasons", []) + (d.extra or {}).get("header_reasons", [])}
                    for d in rows])


def _redis():
    return current_app.extensions["lab_redis"]


def _headers(rows):
    """Headers in wire order, cookie values blanked: a profile keeps the Cookie slot, never a session."""
    return [[k, re.sub(r"=[^;]*", "=REPLACED", v) if k.lower() == "cookie" else v] for k, v in rows]


@bp.route("/capture")
def capture_page():
    """Open in YOUR browser to save it as a real-user profile. A capture id ties the three requests together."""
    cid = secrets.token_urlsafe(12)
    _redis().set(f"lab:capture:{cid}:navigation", json.dumps([[k, v] for k, v in request.headers]), ex=3600)
    return render_template("sensor/capture.html", cid=cid)


@bp.route("/capture/echo")
def capture_echo():
    cid = request.args.get("cid", "")[:32]
    _redis().set(f"lab:capture:{cid}:fetch", json.dumps([[k, v] for k, v in request.headers]), ex=3600)
    return jsonify(ok=True)


@bp.route("/capture/save", methods=["POST"])
def capture_save():
    data = request.get_json(silent=True) or {}
    cid = str(data.get("cid", ""))[:32]
    name = re.sub(r"[^a-z0-9-]", "-", str(data.get("name", "my-browser")).lower())[:40]
    nav, fetch = (_redis().get(f"lab:capture:{cid}:{k}") for k in ("navigation", "fetch"))
    if not nav or not fetch:
        return jsonify(error="reload /lab/capture first"), 400
    profile = {"name": f"captured-{name}", "description": "Captured from a real browser with /lab/capture",
               "source": f"captured with /lab/capture on {date.today().isoformat()}",
               "navigation_headers": _headers(json.loads(nav)), "fetch_headers": _headers(json.loads(fetch)),
               "post_headers": _headers(request.headers),
               "signals": data.get("signals"), "interaction": data.get("interaction")}
    os.makedirs(PROFILES_DIR, exist_ok=True)
    path = os.path.join(PROFILES_DIR, f"{profile['name']}.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)
    return jsonify(ok=True, path=os.path.relpath(path, LAB))


def init(app):
    app.context_processor(lambda: {"sensor_nonce": _nonce})
    hooks.slot("body_end", "sensor/script.html")
    hooks.telemetry.register("sensor", _on_sensor)
    app.register_blueprint(bp)              # under /lab/: ungated and loopback-only by default
