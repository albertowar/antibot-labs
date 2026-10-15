"""
Chapter 4 extension: the store as an operator sees it. What this module adds (no starter file is
edited):

    enricher           resolves the request's operational state (defenses/ops.py): the lab calendar
                       from `Lab-Week` / `Lab-Clock` (the edge drops every other X-Lab-* header, so
                       the replayer uses its own names; they are removed from the headers the
                       layers see), the operator's overrides, the known-good flag. While the
                       operator has the campaign layer on, it also checks the password of every
                       login attempt, also the ones the gate is about to challenge, so the layer can
                       count failures (the cost: one password hash more per attempt).
    GET  /metrics      Prometheus exposition of the defender's own system (defenses/metrics.py).
                       Ungated, readable with curl; `docker compose --profile monitoring` scrapes it.
    POST /lab/ops/new-week   expire the windowed counters (velocity, replay, fingerprint reuse,
                       campaign): they are minutes of wall clock, and a lab week runs in seconds
    POST /lab/ops/reset      back to the start of the chapter: config, corpus refresh, analyst labels
                       and models (the store's own POST /lab/reset knows nothing about those)
    GET  /lab/ops/state      the operator's state: config, model roles, corpus updates, last clock
    after_request      counts scored sign-ins and password outcomes for /metrics

Every decision row carries `week`, `clock`, `known_good`, `signals`, `cluster`, `tel`, `edge_type`
and `model` in its `extra` (the checks put them there), which is what tools/report.py reads.
"""

import glob
import os

from flask import Blueprint, g, jsonify, request

from defenses import attempt, config, corpus, metrics, ops, registry
from demo_site import hooks
from demo_site.models import User
from demo_site.seed import check_password

LOGIN_PATHS = ("/login", "/api/login")
CALENDAR_HEADERS = ("lab-week", "lab-clock")
_last = {"week": 0, "clock": 0}
bp = Blueprint("ops", __name__)


def _int(value):
    try:
        return int(value or 0)
    except ValueError:
        return 0


def enrich(ctx):
    week, clock = _int(request.headers.get("Lab-Week")), _int(request.headers.get("Lab-Clock"))
    if clock:
        _last.update(week=week, clock=clock)
    ctx.headers[:] = [(k, v) for k, v in ctx.headers if k.lower() not in CALENDAR_HEADERS]
    ops.begin(ctx, week, clock)
    if ctx.method == "POST" and ctx.path in LOGIN_PATHS and ctx.attrs["ops"]["cfg"].get("campaign"):
        from flask import current_app
        email, password = attempt.credentials(ctx)
        user = User.query.filter_by(email=email).first()
        ok = check_password(user, password, current_app.config["LAB"].hash_iters)
        ctx.attrs["ops_cred"] = "valid" if ok else ("wrong_password" if user is not None else "unknown_user")
        ctx.note(cred=ctx.attrs["ops_cred"])


def observe(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or request.path not in LOGIN_PATHS:
        return response
    n = ctx.notes
    if n.get("login") in ("ok", "fail"):
        metrics.observe_login("valid" if n["login"] == "ok" else n.get("login_reason", "wrong_password"))
    if n.get("cleared") or not g.decisions:
        return response                         # the retry after a solved challenge is the same attempt
    outcome = g.outcome or ("deceived" if g.deceive else "served")
    action = {"challenged": n.get("rung", "pow"), "deceived": "block", "blocked": "block"}.get(outcome, "allow")
    metrics.observe_decision(n.get("signals") or {}, action, bool(n.get("known_good")), n.get("model"), g.gate_ms)
    return response


@bp.route("/metrics")
def prometheus_metrics():
    from flask import Response
    built = corpus.snapshot().get("built_week", 0)
    refreshed = corpus.updates().get("refreshed_week", {})
    for name in ("asn_database", "header_order", "ja4_table"):
        metrics.corpus_age.labels(corpus=name).set((_last["week"] or 1) - refreshed.get(name, built))
    body, content_type = metrics.render()
    return Response(body, mimetype=content_type)


@bp.route("/lab/ops/new-week", methods=["POST"])
def new_week():
    from flask import current_app
    deleted = 0
    redis = current_app.extensions["lab_redis"]
    for k in list(redis.scan_iter("lab:ops:w:*")):
        deleted += redis.delete(k)
    return jsonify(ok=True, deleted_keys=deleted)


@bp.route("/lab/ops/reset", methods=["POST"])
def reset():
    config.clear()
    corpus.clear()
    removed = []
    paths = [os.path.join(config.LAB, "data", "labels.jsonl"), registry.MANIFEST,
             os.path.join(registry.MODELS_DIR, ".prev_prod")] + glob.glob(os.path.join(registry.MODELS_DIR, "model_v*.txt"))
    for path in paths:
        if os.path.exists(path):
            os.remove(path)
            removed.append(os.path.relpath(path, config.LAB))
    _last.update(week=0, clock=0)
    return jsonify(ok=True, removed=removed)


@bp.route("/lab/ops/state")
def state():
    return jsonify(config=config.load(), effective=config.effective(_last["clock"] or None),
                   roles=registry.load()["roles"], corpus_updates=corpus.updates(), last=_last)


def init(app):
    hooks.enricher(lambda ctx: enrich(ctx))
    hooks.ungate("/metrics")
    app.register_blueprint(bp)
    app.after_request(observe)         # registered after the gate's, so it runs BEFORE the gate stamps the response
