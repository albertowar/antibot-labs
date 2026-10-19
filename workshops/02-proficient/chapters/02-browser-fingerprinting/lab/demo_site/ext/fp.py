"""
Chapter 2 extension: the fingerprint collector on the sign-up page.

New accounts are what a sign-up farm wants (loyalty points, early drop access, a welcome offer),
so the defense sits on the sign-up action. What this module adds (no starter file is edited):

    form:register slot     fp/script.html loads static/js/fp.js with this session's nonce on the
                           sign-up page; the collector reports raw observations, judges nothing
    telemetry "fp"         POST /api/telemetry {"kind": "fp", "nonce": ..., ...}: the nonce must be
                           this session's; the payload and the headers it arrived with become the
                           session's fingerprint record (defenses/fingerprint.py)
    after_request          when POST /register or POST /api/register succeeds, remember which device
                           it came from, at every level (L3 and L4 read this history). The starter's
                           hooks.on_action(...) is never called by a route, so this is the workaround.
    /lab/fp/check          your own browser's fingerprint, and how every level judges it
    /lab/fp/me             the same as JSON (the session's record judged at levels 1-4)
    /lab/fp/profile        download your fingerprint as a real-user profile for tools/profiles/
    /lab/fp/dashboard      sign-ups by level and verdict, and the most-reused devices
    /lab/fp/logs           the last sign-up decisions with their reasons

The /lab/ routes are lab pages: never gated, loopback only. In production never tell a client which
rule caught it; the collector itself never learns its verdict.
"""

import hashlib
import hmac
import json

from flask import Blueprint, abort, current_app, g, jsonify, make_response, render_template, request

from demo_site import gate, hooks

REGISTER_PATHS = ("/register", "/api/register")

bp = Blueprint("lab_fp", __name__, url_prefix="/lab/fp")


def _defenses():
    from defenses import fingerprint, stable_id      # through the modules: defenses/ is hot-reloaded
    return fingerprint, stable_id


def _nonce_for(sid):
    """A per-session value the page embeds and the payload must echo back (binds a payload to a session)."""
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, sid.encode(), hashlib.sha256).hexdigest()[:16]


def _nonce():
    """Called by fp/script.html on every page view that carries the collector."""
    ctx = getattr(g, "ctx", None)
    return _nonce_for(ctx.session.sid) if ctx is not None else ""


def _on_fp(ctx, payload):
    """Keep the report only if it carries this session's nonce. Returns the IDs the server derives."""
    fingerprint, ids = _defenses()
    fp = {k: v for k, v in payload.items() if k != "kind"}
    if fp.get("nonce") != _nonce_for(ctx.session.sid):
        return {"stored": False, "reason": "payload is not from this session"}
    headers = {h: ctx.header(h) for h in fingerprint.KEPT_HEADERS if ctx.header(h) is not None}
    fingerprint.store_record(ctx, fp, headers)
    # fp_id is the noise-resistant core_id: what W2 Ch6 binds to an account
    return {"stored": True, "fp_id": ids.core_id(fp), "stable_id": ids.stable_id(fp),
            "device_class": ids.device_class(fp)}


def _remember_signup(response):
    ctx = getattr(g, "ctx", None)
    if (ctx is None or request.method != "POST" or request.path not in REGISTER_PATHS
            or response.status_code not in (201, 302)):
        return response
    body = request.get_json(silent=True) if request.is_json else request.form
    fingerprint, _ = _defenses()
    fingerprint.remember_account(ctx, str((body or {}).get("email", "")).strip().lower())
    return response


def _session_ctx():
    """The calling browser's session (lab pages are ungated, so build the Ctx by hand)."""
    return gate.build_ctx(current_app)


@bp.route("/check")
def check():
    """Your fingerprint and how each level judges it. Builds a session so the collector can post."""
    g.ctx = gate.build_ctx(current_app)
    return render_template("fp/check.html")


@bp.route("/me")
def me():
    fingerprint, ids = _defenses()
    ctx = _session_ctx()
    rec = fingerprint.record(ctx)
    if rec is None:
        return jsonify(error="no fingerprint yet: open /lab/fp/check or /register first"), 404
    fp = rec["payload"]
    return jsonify(level=current_app.config["LAB"].defense_level, link_mode=_policy().LINK_MODE,
                   fp_id=ids.core_id(fp), stable_id=ids.stable_id(fp), device_class=ids.device_class(fp),
                   headers=rec["headers"], payload=fp, levels=fingerprint.judge(ctx))


def _policy():
    from defenses import policy
    return policy


@bp.route("/profile")
def profile():
    """Download your fingerprint as a real-user profile for tools/profiles/."""
    fingerprint, _ = _defenses()
    rec = fingerprint.record(_session_ctx())
    if rec is None:
        abort(404)
    fp = rec["payload"]
    out = {"cohort": "you", "provenance": "captured",
           "description": f"Captured from {fp.get('nav', {}).get('userAgent', '?')[:80]}",
           "headers": rec["headers"], "users": [{"payload": fp}]}
    response = make_response(json.dumps(out, indent=1))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = "attachment; filename=you.json"
    return response


def _signup_rows(limit):
    from demo_site.models import Decision
    current_app.extensions["decision_log"].flush()
    return (Decision.query.filter(Decision.method == "POST", Decision.path.in_(REGISTER_PATHS))
            .order_by(Decision.id.desc()).limit(limit).all())


@bp.route("/dashboard")
def dashboard():
    """Sign-up outcomes by level and verdict, and the most-reused devices (accounts created today)."""
    counts = {}
    for d in _signup_rows(5000):
        key = (d.level, d.action, d.status)
        counts[key] = counts.get(key, 0) + 1
    redis = current_app.extensions["lab_redis"]
    reused = sorted(((k.rsplit(":", 1)[1], redis.zcard(k)) for k in redis.scan_iter("lab:fp:acct:*")),
                    key=lambda x: -x[1])[:5]
    return jsonify(level=current_app.config["LAB"].defense_level, link_mode=_policy().LINK_MODE,
                   signups=[{"level": lv, "verdict": a, "status": s, "count": c} for (lv, a, s), c in sorted(counts.items())],
                   most_reused_fingerprints=[{"stable_id": sid, "accounts": n} for sid, n in reused])


@bp.route("/logs")
def logs():
    """The last N sign-up decisions with the reasons the fingerprint layers gave."""
    n = min(500, request.args.get("limit", 50, type=int))
    return jsonify([{"ts": d.ts.isoformat() + "Z", "sid": (d.sid or "")[:6], "level": d.level, "path": d.path,
                     "status": d.status, "score": d.score, "action": d.action, "signals": d.signals,
                     "reasons": (d.extra or {}).get("fp_reasons", [])} for d in _signup_rows(n)])


def init(app):
    app.context_processor(lambda: {"fp_nonce": _nonce})
    hooks.slot("form:register", "fp/script.html")
    hooks.telemetry.register("fp", _on_fp)
    app.after_request(_remember_signup)
    app.register_blueprint(bp)              # under /lab/: ungated and loopback-only by default
