"""
Capstone feature module: the supply-chain surface (W3 Ch5). No starter file is edited, and nothing here decides
anything (defenses/supply_chain.py owns the policy and the check).

    slot body_end         the third-party tag: static/js/runtime_monitor.js first (so it sees the other script's
                          calls), then static/js/analytics-helper.js, the vendor file a skimmer rides in on
    after_request         from level 7, every HTML page gets the Content-Security-Policy that
                          defenses/supply_chain.csp_header() builds (enforcing or Report-Only, per its TODO), and
                          every <script> in the page carries the response's nonce
    POST /api/script-violation   the CSP report-uri and the runtime monitor's sink: the browser POSTs here when it
                          refuses a connection the page tried to make. Ungated, because a session the defenses
                          dislike must still be able to deliver its reports; it is rate-capped and only accepts a
                          report for a session that exists.

The skimmer (static/js/skimmer.js) is the payload attacks/round3_skimmer.py adds to the vendor tag in a real
browser; it is never part of the store. The collector it exfiltrates to is fictional and is never contacted:
labclient.browser_context aborts every request that leaves this machine.

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import importlib
import json
import re
import secrets

from flask import Blueprint, current_app, g, jsonify, request

from demo_site import hooks

bp = Blueprint("supply9", __name__)
_SCRIPT_TAG = re.compile(r"<script(?![^>]*\bnonce=)", re.I)


def _defense(name):
    return importlib.import_module(f"defenses.{name}")


def _decorate(response):
    """Level 7: the CSP header, and the nonce on every <script> of the page."""
    if getattr(g, "ctx", None) is None or response.mimetype != "text/html" or response.direct_passthrough:
        return response
    if current_app.config["LAB"].defense_level < 7:
        return response
    nonce = secrets.token_urlsafe(12)
    name, value = _defense("supply_chain").csp_header(nonce)
    response.headers[name] = value
    response.set_data(_SCRIPT_TAG.sub(f'<script nonce="{nonce}"', response.get_data(as_text=True)))
    return response


@bp.post("/api/script-violation")
def script_violation():
    """CSP report sink (level 7). Browsers send application/csp-report, the monitor sends JSON."""
    redis = current_app.extensions["lab_redis"]
    sid = request.cookies.get("sid", "")
    if sid and redis.exists(f"lab:s:{sid}"):
        body = request.get_json(force=True, silent=True) or {}
        _defense("supply_chain").record_violation(redis, sid, body.get("csp-report", body))
    return ("", 204)


@bp.get("/lab/supply/me")
def my_reports():
    """The violation reports recorded for YOUR session (cookie `sid`), for the debrief."""
    redis = current_app.extensions["lab_redis"]
    sid = request.cookies.get("sid", "")
    reports = [json.loads(r) for r in redis.lrange(f"lab:csp:viol:{sid}", 0, -1)] if sid else []
    return jsonify(sid=sid, reports=reports, policy=_defense("supply_chain").csp_header("<nonce>")[0])


def init(app):
    app.register_blueprint(bp)
    hooks.ungate("/api/script-violation")
    hooks.slot("body_end", "supply9/tags.html")
    app.after_request(_decorate)
