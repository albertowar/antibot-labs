"""
Chapter 4 feature module: everything the header defenses need from the store that is not a check.

    app.after_request   Accept-CH (and optionally Critical-CH) on HTML pages, plus the `ch_offered`
                        cookie that remembers the store asked. Only while the accept_ch check is
                        on the active ladder (level 4 in this lab): a store that does not check the
                        hints should not ask for them, because every hint costs the visitor bytes
                        on every request and widens the fingerprint you send to every third party
                        that sees your requests.
    enricher            writes the User-Agent into the decision log at every level
    /lab/headers/check  how THIS request scores, check by check and level by level, plus the headers
                        in arrival order. Save its output as tools/profiles/<browser>.json.
    /lab/headers/logs   the last 50 scored requests with their reasons (the old /header-logs)

The two routes are lab pages: /lab/ is already ungated, so they are never blocked, whatever
your headers look like. In production never tell a client which rule caught it.
"""

from flask import Blueprint, current_app, jsonify, request

from defenses import policy, reloader
from defenses.pipeline import Verdict

from .. import gate, hooks
from ..models import Decision


def _ladder(cfg):
    if cfg.lab_reload:
        return reloader.ladder()
    from defenses import ladder
    return ladder.LADDER


def _hints_enforced(cfg):
    """True while a check named accept_ch is enforced at the current level."""
    return any(c.name == "accept_ch" for k, checks in _ladder(cfg).items() if k <= cfg.defense_level for c in checks)


def _offer_client_hints(response):
    """Ask Chromium for the high-entropy hints on HTML, and remember (in a cookie) that we asked."""
    cfg = current_app.config["LAB"]
    if response.mimetype != "text/html" or not _hints_enforced(cfg):
        return response
    response.headers["Accept-CH"] = ", ".join(policy.ACCEPT_CH_HINTS)
    # Hints change the response only if the server uses them to vary it; Vary keeps shared caches honest anyway.
    response.headers.add("Vary", ", ".join(policy.ACCEPT_CH_HINTS))
    if policy.CRITICAL_CH:
        # Chromium retries THIS navigation with the hints before rendering, so even the first request carries them.
        response.headers["Critical-CH"] = policy.ACCEPT_CH_HINTS[0]
    if policy.OFFERED_COOKIE not in request.cookies:
        response.set_cookie(policy.OFFERED_COOKIE, "1", httponly=True, samesite="Lax")
    return response


def _note_ua(ctx):
    """Runs at every level, so the log has the User-Agent even at level 0 where no check runs."""
    ctx.note(ua=ctx.ua.raw[:120])


def _signals(out):
    if out is None:
        return []
    return list(out.signals) if isinstance(out, Verdict) else list(out)


def init(app):
    hooks.enricher(_note_ua)
    app.after_request(_offer_client_hints)
    bp = Blueprint("headers", __name__, url_prefix="/lab/headers")      # /lab/ is already ungated

    @bp.route("/check")
    def check():
        """Run every check on the ladder against this very request: what each layer thinks, and the total per level."""
        cfg = current_app.config["LAB"]
        ctx = gate.build_ctx(current_app)
        rows, by_level, total = [], {}, 0
        for k, checks in sorted(_ladder(cfg).items()):
            for c in checks:
                try:
                    sigs = _signals(c.fn(ctx))
                except Exception as e:                        # a broken check must not break the page
                    sigs = []
                    rows.append({"level": k, "check": c.name, "name": "error", "points": 0, "detail": repr(e)})
                rows += [{"level": k, "check": c.name, "name": s.name, "points": s.points, "detail": s.detail} for s in sigs]
                total += sum(s.points for s in sigs)
            by_level[str(k)] = {"score": min(100, total), "action": policy.decide(min(100, total), [], k)}
        here = by_level.get(str(cfg.defense_level), {"score": 0, "action": "allow"})
        return jsonify(level=cfg.defense_level, score=here["score"], verdict=here["action"], by_level=by_level, signals=rows,
                       # a list, not a dict, so the arrival order is visible
                       headers_received=[[n, v] for n, v in ctx.headers])

    @bp.route("/logs")
    def logs():
        """The last N scored requests (default 50) with the reasons the header checks gave."""
        log = current_app.extensions.get("decision_log")
        log and log.flush()
        n = min(500, request.args.get("limit", 50, type=int))
        rows = Decision.query.order_by(Decision.id.desc()).limit(n).all()
        return jsonify([{"id": d.id, "ts": d.ts.isoformat() + "Z", "level": d.level, "path": d.path, "status": d.status,
                         "ua": (d.extra or {}).get("ua", ""), "score": d.score, "action": d.action, "signals": d.signals,
                         "reasons": (d.extra or {}).get("header_reasons", [])} for d in rows])

    app.register_blueprint(bp)
