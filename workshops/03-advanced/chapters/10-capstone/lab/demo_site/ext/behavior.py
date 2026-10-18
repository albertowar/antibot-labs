"""
Chapter 3 extension: behavioral telemetry on the drop page.

What it adds to the store (no starter file is edited):

    drop.html override     ext/templates/drop.html draws the reservation form at
                           fixed positions inside #behavior-form and loads
                           static/js/behavior.js, the collector
    behavior_layout()      template helper: picks this page view's layout
                           (defenses.behavior.new_layout, jittered from Level 4)
                           and remembers it in the session
    telemetry "behavior"   POST /api/telemetry {"kind": "behavior", ...}: stores the
                           record and its replay signature at every level
    /lab/behavior/...      debug routes (loopback only, never scored):
                             sessions        the last reservations: level, verdict, signals, size
                             trace/<sid>     raw telemetry + features ("latest" works)
                             view/<sid>      draws the path, clicks, speed profiles and keys

The scoring itself lives in defenses/behavior_l1..l5.py, wired by defenses/ladder.py.
The lab routes never read the ground-truth actor label; tools/save_trace.py does
that from /lab/decisions, like every other tool.
"""

import json

from flask import Blueprint, abort, current_app, g, jsonify, render_template, request

from demo_site import hooks

bp = Blueprint("lab_behavior", __name__)


def _behavior():
    from defenses import behavior          # through the module: defenses/ is hot-reloaded
    return behavior


def _layout():
    """Called by drop.html on every page view: a fresh layout for this session."""
    b = _behavior()
    layout = b.new_layout(current_app.config["LAB"].defense_level)
    ctx = getattr(g, "ctx", None)
    if ctx is not None:
        ctx.session.set(b.LAYOUT_KEY, json.dumps(layout))
    return layout


def _on_telemetry(ctx, payload):
    b = _behavior()
    raw = ctx.session.get(b.LAYOUT_KEY)
    if not raw:
        return {"stored": False, "reason": "no drop page in this session"}
    b.remember(ctx.redis, ctx.session.sid, payload, json.loads(raw),
               current_app.config["LAB"].defense_level, request.content_length or 0)
    return {"stored": True}


def _redis():
    return current_app.extensions["lab_redis"]


def _resolve(sid):
    if sid == "latest":
        newest = _redis().lindex(_behavior().RECENT_KEY, 0)
        if newest is None:
            abort(404)
        return newest
    return sid


def _decision(sid):
    """What the gate decided for this session's last reservation (from the decision log)."""
    from demo_site.models import Decision
    current_app.extensions["decision_log"].flush()
    row = (Decision.query.with_entities(Decision.level, Decision.action, Decision.score, Decision.signals,
                                        Decision.outcome, Decision.ms)
           .filter(Decision.sid == sid, Decision.method == "POST", Decision.path.like("/drop/%"))
           .order_by(Decision.id.desc()).first())
    if row is None:
        return None
    return {"level": row.level, "action": row.action, "score": row.score, "signals": row.signals,
            "outcome": row.outcome, "gate_ms": round(row.ms or 0, 2)}


@bp.route("/lab/behavior/sessions")
def sessions():
    n = int(request.args.get("n", 30))
    out = []
    for sid in _redis().lrange(_behavior().RECENT_KEY, 0, n - 1):
        raw = _redis().get(_behavior().TRACES_KEY + sid)
        if raw is None:
            continue
        rec = json.loads(raw)
        out.append({"sid": sid, "level": rec["level"], "bytes": rec["bytes"],
                    "points": len(rec["telemetry"].get("pointer", [])), "decision": _decision(sid)})
    return jsonify(level=current_app.config["LAB"].defense_level, sessions=out)


@bp.route("/lab/behavior/trace/<sid>")
def trace(sid):
    sid = _resolve(sid)
    raw = _redis().get(_behavior().TRACES_KEY + sid)
    if raw is None:
        abort(404)
    rec = json.loads(raw)
    from defenses.behavior_features import extract
    rec["features"] = extract(rec["telemetry"], rec["layout"])
    rec["decision"] = _decision(sid)
    return jsonify(rec)


@bp.route("/lab/behavior/view/<sid>")
def view(sid):
    return render_template("behavior/view.html", sid=_resolve(sid))


def init(app):
    app.context_processor(lambda: {"behavior_layout": _layout})
    hooks.telemetry.register("behavior", _on_telemetry)
    app.register_blueprint(bp)              # under /lab/: ungated and loopback-only by default
