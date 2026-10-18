"""
Capstone feature module: GET /metrics, the Prometheus text exposition (W3 Ch4's signal health, for the capstone).

Used by the optional `prod` profile of docker-compose.yml (Prometheus scrapes this, Grafana draws the signal-health
board) and handy on its own: `curl localhost:5000/metrics`. There is no prometheus_client dependency: the counts come
straight from the decision log and a couple of Redis counters, hand-formatted.

    lab_decisions_total{phase,outcome}   gated decisions by phase and what the client experienced
    lab_layer_triggers_total{layer}      decisions in which each layer (L0 to L7, defenses/layers.py) contributed a signal;
                                         signals from layers above the level (LAB_SHADOW=1) count too, which is what
                                         "shadow mode" is for
    lab_ws_flood_events_total            WebSocket connections cut for flooding
    lab_csp_violations_total             CSP violation reports received
    lab_defense_level                    the running DEFENSE_LEVEL

A layer that never fires during an attack window is a finding (bypassed, or drifted). That is the whole use of the board.
Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import collections

from flask import Blueprint, Response, current_app
from sqlalchemy import func

from defenses import layers
from demo_site import hooks
from demo_site.models import Decision, db

bp = Blueprint("metrics9", __name__)


@bp.get("/metrics")
def metrics():
    log = current_app.extensions.get("decision_log")
    if log is not None:
        log.flush()
    redis = current_app.extensions["lab_redis"]
    lines = ["# HELP lab_decisions_total Gated decisions by phase and outcome.", "# TYPE lab_decisions_total counter"]
    for phase, outcome, n in db.session.query(Decision.phase, Decision.outcome, func.count(Decision.id)) \
            .group_by(Decision.phase, Decision.outcome).all():
        lines.append(f'lab_decisions_total{{phase="{phase}",outcome="{outcome}"}} {n}')
    fired = collections.Counter({layer: 0 for layer in layers.LAYERS})
    for signals, shadow in db.session.query(Decision.signals, Decision.shadow).filter(
            (Decision.signals != "") | (Decision.shadow != "")).all():
        flags = [f for f in (signals or "").split(",") + (shadow or "").split(",") if f]
        for layer in {layers.layer_of(f) for f in flags}:
            fired[layer] += 1
    lines += ["# HELP lab_layer_triggers_total Decisions where each layer contributed a signal.",
              "# TYPE lab_layer_triggers_total counter"]
    lines += [f'lab_layer_triggers_total{{layer="{layer}"}} {n}' for layer, n in sorted(fired.items())]
    lines += ["# HELP lab_ws_flood_events_total WebSocket connections cut for flooding.",
              "# TYPE lab_ws_flood_events_total counter", f"lab_ws_flood_events_total {int(redis.get('lab:ws:flood') or 0)}",
              "# HELP lab_csp_violations_total CSP violation reports received.",
              "# TYPE lab_csp_violations_total counter", f"lab_csp_violations_total {int(redis.get('lab:csp:count') or 0)}",
              f"lab_defense_level {current_app.config['LAB'].defense_level}"]
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")


def init(app):
    app.register_blueprint(bp)
    hooks.ungate("/metrics")
