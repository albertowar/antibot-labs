"""
Lab-only routes. Loopback only (the lab edge refuses everything else), never
part of the production surface, and skipped by the gate.

    GET  /whoami            what the edge resolved for you, your session, the last verdict
    GET  /lab/status        level, counts, loaded extensions, registered hooks
    GET  /lab/config        the running Config
    GET  /lab/decisions     the decision log (?actor=bot:&limit=200&since=<iso>)
    GET  /lab/scoreboard    per-actor outcomes: bots stopped vs shoppers hurt
    POST /lab/reset         ?mode=state (default: drop stock, lab rows, Redis) | full (reseed)
    POST /lab/level         {"level": N}
    GET  /lab/mailbox/<email>  reset tokens and OTPs the store "emailed"
    GET  /lab/account/changes  account changes (?user=<email|id>&status=&kind=), oldest first
    POST /lab/account/changes/<id>/release   apply a pending (held) change now
"""

import json
import os
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from defenses import reloader, store

from .. import hooks
from .. import account as acct
from ..models import AccountChange, Decision, Order, Product, Review, User, db
from ..seed import reset_state, seed_all

bp = Blueprint("lab", __name__)


def _log():
    return current_app.extensions.get("decision_log")


@bp.route("/whoami")
def whoami():
    from .. import gate
    ctx = gate.build_ctx(current_app)
    last = Decision.query.filter_by(sid=ctx.session.sid).order_by(Decision.id.desc()).first()
    return jsonify(ip=ctx.edge.ip, asn=ctx.edge.asn, org=ctx.edge.org, country=ctx.edge.country, pool=ctx.edge.pool,
                   ja4=ctx.edge.ja4, ja4_source=ctx.edge.ja4_source, xff_claimed=ctx.edge.xff_claimed, actor=request.environ.get("lab.actor", "you"),
                   session=ctx.session.sid, session_age_s=round(ctx.session.age_seconds, 1), user=ctx.user.email if ctx.user else None, auth=ctx.auth,
                   level=current_app.config["LAB"].defense_level, ua=ctx.ua.family, last_decision=last.to_dict() if last else None)


@bp.route("/lab/status")
def status():
    cfg = current_app.config["LAB"]
    ladder = reloader.ladder() if cfg.lab_reload else __import__("defenses.ladder", fromlist=["LADDER"]).LADDER
    _log() and _log().flush()
    return jsonify(store="Kestrel Outfitters", level=cfg.defense_level, shadow=cfg.lab_shadow,
                   ladder={str(k): [c.name for c in v] for k, v in sorted(ladder.items())},
                   extensions=current_app.extensions.get("lab_ext", []), challenges=hooks.challenges.names(),
                   telemetry_kinds=hooks.telemetry.kinds(), slots={k: len(v) for k, v in hooks.SLOTS.items()},
                   ungated=[p for p, m in hooks.UNGATED if m == "skip"],
                   products=Product.query.count(),
                   visible_products=Product.query.filter_by(hidden=False).count(),
                   users=User.query.count(), decisions=Decision.query.count(),
                   orders_this_lab=Order.query.filter(Order.session_id.isnot(None)).count(),
                   drops={p.sku: p.stock for p in Product.query.filter_by(is_drop=True)})


@bp.route("/lab/config")
def config():
    cfg = current_app.config["LAB"]
    return jsonify({k: (v if not k.startswith("secret") else "***") for k, v in cfg.__dict__.items()})


@bp.route("/lab/decisions")
def decisions():
    _log() and _log().flush()
    q = Decision.query
    if request.args.get("actor"):
        q = q.filter(Decision.actor.like(request.args["actor"] + "%"))
    if request.args.get("since"):
        q = q.filter(Decision.ts >= datetime.fromisoformat(request.args["since"].rstrip("Z")))
    if request.args.get("path"):
        q = q.filter(Decision.path == request.args["path"])
    limit = min(5000, request.args.get("limit", 500, type=int))
    rows = q.order_by(Decision.id.desc()).limit(limit).all()
    return jsonify(items=[r.to_dict() for r in reversed(rows)], total=q.count())


def scoreboard_data(since=None):
    _log() and _log().flush()
    q = Decision.query
    if since:
        q = q.filter(Decision.ts >= since)
    board, final = {}, {}
    for d in q.order_by(Decision.id).all():
        final[d.actor or "you"] = d.outcome
        actor = d.actor or "you"
        kind = actor.split(":")[0]
        group = actor.rsplit(":", 1)[0] if kind in ("human", "bot", "legit") and actor.count(":") >= 2 else actor
        row = board.setdefault(group, {"actor": group, "kind": kind, "requests": 0, "served": 0, "purchased": 0,
                                       "blocked": 0, "challenged": 0, "rate_limited": 0, "deceived": 0, "other": 0,
                                       "score_sum": 0, "ms_sum": 0.0})
        row["requests"] += 1
        # Known outcomes keep their fixed column; a chapter-specific outcome (an ext setting g.outcome,
        # e.g. paywalled/charged/mazed/held) gets its own column instead of being folded into "other".
        oc = d.outcome or "other"
        row[oc] = row.get(oc, 0) + 1
        row["score_sum"] += d.score or 0
        row["ms_sum"] += d.ms or 0
    for row in board.values():
        row["avg_score"] = round(row["score_sum"] / row["requests"], 1)
        row["avg_ms"] = round(row["ms_sum"] / row["requests"], 2)
        # hooks.stopped_outcome() lets a chapter count its own outcomes (paywalled, mazed) here
        row["stopped"] = sum(row.get(oc, 0) for oc in hooks.STOPPED_OUTCOMES)
    # An individual is hurt if the LAST thing that happened to them was a stop and they bought nothing.
    # A shopper who met a challenge, solved it and carried on is not hurt (that is the challenge working).
    # Only paid orders count: a held order (status="pending") is neither a purchase nor a stop yet.
    oq = Order.query.filter(Order.session_id.isnot(None), Order.status == "paid")
    if since:
        oq = oq.filter(Order.created_at >= since)
    purchases, buyers = {}, set()
    for o in oq:
        actor = o.actor or "you"
        purchases[actor.split(":")[0]] = purchases.get(actor.split(":")[0], 0) + sum(i.qty for i in o.items)
        buyers.add(actor)
    for actor, outcome in final.items():
        kind = actor.split(":")[0]
        group = actor.rsplit(":", 1)[0] if kind in ("human", "bot", "legit") and actor.count(":") >= 2 else actor
        row = board[group]
        row["individuals"] = row.get("individuals", 0) + 1
        row["individuals_hurt"] = row.get("individuals_hurt", 0) + int(outcome in hooks.STOPPED_OUTCOMES and actor not in buyers)
    humans = [r for r in board.values() if r["kind"] == "human"]
    bots = [r for r in board.values() if r["kind"] == "bot"]
    summary = {"humans_hurt": sum(r.get("individuals_hurt", 0) for r in humans),
               "humans": sum(r.get("individuals", 0) for r in humans),
               "human_requests_stopped": sum(r["stopped"] for r in humans),
               "human_requests": sum(r["requests"] for r in humans),
               "bots_stopped": sum(r["stopped"] for r in bots), "bot_requests": sum(r["requests"] for r in bots),
               "bot_served": sum(r["served"] + r["purchased"] for r in bots), "purchases": purchases,
               "drops": {p.sku: p.stock for p in Product.query.filter_by(is_drop=True)}}
    # Welcome automation (verified crawlers, uptime monitors) labels itself legit:<name>:<nn>.
    # A stopped crawler is a false positive, not a bot stopped, so it gets its own columns —
    # added only when such actors exist, so every two-kind scoreboard is unchanged.
    legit = [r for r in board.values() if r["kind"] == "legit"]
    if legit:
        summary.update(legit=sum(r.get("individuals", 0) for r in legit),
                       legit_hurt=sum(r.get("individuals_hurt", 0) for r in legit),
                       legit_requests=sum(r["requests"] for r in legit),
                       legit_requests_stopped=sum(r["stopped"] for r in legit))
    return {"actors": sorted(board.values(), key=lambda r: (r["kind"], r["actor"])), "summary": summary}


@bp.route("/lab/scoreboard")
def scoreboard():
    since = datetime.fromisoformat(request.args["since"].rstrip("Z")) if request.args.get("since") else None
    return jsonify(scoreboard_data(since))


@bp.route("/lab/reset", methods=["POST"])
def reset():
    cfg = current_app.config["LAB"]
    mode = request.args.get("mode", "state")
    _log() and _log().flush()
    store.flush_lab_state(current_app.extensions["lab_redis"])
    if mode == "full":
        db.drop_all()
        out = seed_all(cfg.lab_seed, cfg.drop_stock, cfg.hash_iters)
    else:
        reset_state(request.args.get("stock", cfg.drop_stock, type=int))
        out = {"reset": "state"}
    try:
        if os.path.exists(cfg.decision_log):
            os.truncate(cfg.decision_log, 0)
    except OSError:
        pass
    for fn in hooks.RESET_HOOKS:                 # exts drop/reseed the tables and keys they own
        fn(current_app)
    return jsonify(ok=True, **out)


@bp.route("/lab/level", methods=["POST"])
def level():
    body = request.get_json(silent=True) or {}
    cfg = current_app.config["LAB"]
    n = int(body.get("level", request.args.get("level", cfg.defense_level)))
    current_app.config["LAB"] = cfg.__class__(**dict(cfg.__dict__, defense_level=n))
    return jsonify(ok=True, level=n)


@bp.route("/lab/reload", methods=["POST"])
def reload():
    ladder = reloader.ladder()
    return jsonify(ok=True, ladder={str(k): [c.name for c in v] for k, v in sorted(ladder.items())})


@bp.route("/lab/mailbox/<path:email>")
def mailbox(email):
    r = current_app.extensions["lab_redis"]
    msgs = [json.loads(m) for m in r.lrange(f"lab:mailbox:{email.lower()}", 0, -1)]
    return jsonify(email=email, messages=msgs)


@bp.route("/lab/account/changes")
def account_changes():
    q = AccountChange.query
    who = request.args.get("user", "")
    if who:
        u = User.query.get(int(who)) if who.isdigit() else User.query.filter_by(email=who.lower()).first()
        q = q.filter(AccountChange.user_id == (u.id if u else -1))
    for col in ("status", "kind"):
        if request.args.get(col):
            q = q.filter(getattr(AccountChange, col) == request.args[col])
    rows = q.order_by(AccountChange.id).limit(min(5000, request.args.get("limit", 500, type=int))).all()
    return jsonify(items=[r.to_dict() for r in rows], total=q.count())


@bp.route("/lab/account/changes/<int:cid>/release", methods=["POST"])
def account_change_release(cid):
    """Apply a held change: what a cooling-off clock or a reviewer does in a chapter's lab."""
    change = db.session.get(AccountChange, cid)
    if change is None:
        return jsonify(error={"code": "not_found", "message": "No such change."}), 404
    if change.status != "pending":
        return jsonify(error={"code": "not_pending", "message": f"Change is {change.status}."}), 409
    return jsonify(ok=True, change=acct.release_change(change).to_dict())
