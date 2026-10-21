"""
W4 Ch9 extension: the analyst's request log, the login log and two traps.

What this module adds (no starter file is edited):

    on_response           one row per response into defenses/rule_store.requests_t
                          (contract 1.7's hooks.on_response: it also sees the ungated
                          /static and /img fetches, so asset_ratio is a real feature),
                          with every header the client chose to send, capped at
                          MAX_FIELD_BYTES. 404s included: a probe for a path that does
                          not exist is part of the session's story, and the path is
                          text the client wrote.
    on_action("login")    one row per login ATTEMPT (success or failure) into
                          logins_t: the submitted account name is attacker text too.
    /specials-archive     a honeypot page, linked invisibly from every page footer
                          (hooks.slot) and disallowed in robots.txt: humans never see
                          it, crawlers that ignore robots.txt walk straight in.
    /partner-feed         a robots.txt-disallowed JSON feed: the API-shaped bait.
    on_reset              POST /lab/reset also clears the four analyst tables.

Nothing here decides anything, and nothing here reads the ground-truth actor:
the analyst sees exactly what production logging would give it.
"""

import time

from flask import Blueprint, current_app, jsonify, render_template_string, request

from defenses import rule_store
from demo_site import hooks

UNLOGGED = ("/lab/", "/whoami", "/health", "/favicon.ico")
ASSET_PREFIXES = ("/static/", "/img/")

bp = Blueprint("llm_log", __name__)


def _cap(value):
    """The database is not the resource the flood gets to exhaust."""
    return (value or "")[:rule_store.MAX_FIELD_BYTES]


def _engine():
    # The ext's own engine (and pool) on the same database. Borrowing the app's
    # pool would make every request hold TWO of its connections at once (the
    # route's ORM session plus this insert), and 16 server threads then starve
    # a 15-connection pool: the store stalls for the pool timeout, not the disk.
    from defenses import rule_store
    return rule_store.make_engine()


def _observe(info):
    if info.path.startswith(UNLOGGED):
        return
    if info.ctx is not None:
        sid = info.ctx.session.sid
    else:
        # An ungated asset builds no Ctx; the session cookie the first gated
        # page set still rides the request. No cookie yet: nothing to attach
        # the fetch to, which is also true of a CDN log keyed by session.
        sid = request.cookies.get("sid")
    if not sid:
        return
    edge = info.edge or {}
    with _engine().begin() as conn:
        conn.execute(rule_store.requests_t.insert().values(
            sid=sid, ts=time.time(), method=info.method, path=_cap(info.path),
            status=info.status, ip=edge.get("ip", ""), asn=f"AS{edge.get('asn', 0)} {edge.get('org', '')}"[:80],
            country=edge.get("country", ""),
            ua=_cap(request.headers.get("User-Agent", "")),
            referer=_cap(request.headers.get("Referer", "")),
            accept_language=_cap(request.headers.get("Accept-Language", "")),
            is_asset=int(info.path.startswith(ASSET_PREFIXES)),
            bytes_out=info.response.calculate_content_length() or 0))


def _log_login(ctx, result, response):
    user = result.get("user")
    with _engine().begin() as conn:
        conn.execute(rule_store.logins_t.insert().values(
            sid=ctx.session.sid, ts=time.time(),
            account=_cap(str(ctx.notes.get("email", ""))),
            user_id=user.id if user else None, ok=int(result.get("ok", False))))
    return None


ARCHIVE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Specials archive · Kestrel Outfitters</title></head><body>
<h1>Specials archive</h1>
<p>Past seasonal specials. Nothing here is on sale.</p>
<ul>{% for y in range(2019, 2026) %}<li>Autumn {{ y }} clearance (ended)</li>{% endfor %}</ul>
</body></html>"""


@bp.route("/specials-archive")
def specials_archive():
    return render_template_string(ARCHIVE)


@bp.route("/partner-feed")
def partner_feed():
    # The API-shaped bait: robots.txt disallows it, no page links it as a button.
    return jsonify({"feed": "partner", "products": [], "note": "ask your account manager for access"})


def _reset(app):
    """POST /lab/reset: the analyst's tables, the rules the ops loop activated, the run windows.
    A checkpoint must start from the committed baseline or its numbers depend on the last run."""
    import json
    import os
    rule_store.clear(_engine())
    lab = rule_store.LAB
    with open(os.path.join(lab, "rules", "active.json"), "w") as fh:
        json.dump({"version": 0, "rules": []}, fh, indent=2)
        fh.write("\n")
    for rel in ("rules/pending.json", "rules/audit.jsonl", "data/runs.json"):
        path = os.path.join(lab, rel)
        if os.path.exists(path):
            os.remove(path)


def _tune_sqlite(engine):
    """WAL + NORMAL sync, so one event INSERT per response does not serialize the store.
    (The analyst's tools read the same file while the simulators write; without WAL a
    drop-day wave stalls behind the journal lock and requests time out.)"""
    if engine.url.get_backend_name() != "sqlite":
        return
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _pragmas(conn, _):
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()
    with engine.connect() as conn:          # apply to the pool's existing connection too
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")


def init(app):
    rule_store.create_tables(_engine())
    with app.app_context():
        _tune_sqlite(app.extensions["sqlalchemy"].engine)   # the store's own writes benefit too
    hooks.on_response(_observe)
    hooks.on_action("login", _log_login)
    hooks.robots(lambda: ["Disallow: /partner-feed", "Disallow: /specials-archive"])
    hooks.slot("body_end", "llm_log/honeypot.html")
    hooks.on_reset(_reset)
    app.register_blueprint(bp)
