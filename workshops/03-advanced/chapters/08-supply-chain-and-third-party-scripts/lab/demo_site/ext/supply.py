"""
W3 Ch8 extension: the supply-chain slice of the store.

The store is the starter's. This chapter works on a SLICE of it on purpose: the two forms a skimmer
targets (`form#checkout` with a card field, `form#login-form` with a password) and a third-party
script include the store hosts. Everything below is about what those pages carry to the browser.

What this module adds
  - the include: a vendor <script> (/static/vendor/analytics-helper.js) and the store's first-party
    bundle (/static/js/shop-bundle.js), placed with the `body_end` slot; the monitor goes in `head`.
  - the compromise, ALREADY in place (you never write the skimmer): which file the vendor serves
    (`vendor`: clean | compromised | updated) and which exfil technique it uses (`variant`), set
    through POST /lab/supply/scenario so a round is a request, not a restart.
  - the response side of the defenses: it builds one PageControls per HTML response, runs the
    ladder's "page" phase over it (defenses/ladder.py; see defenses/page_controls.py) and turns the
    result into the Content-Security-Policy header, the nonce on every <script>, the integrity
    attribute and the monitor script.
  - the defender's inboxes: POST /lab/supply/csp-report (the CSP report-uri) and the "script_violation"
    telemetry kind (the runtime monitor), read back at GET /lab/supply/csp-reports and /violations.

Lab routes (loopback only, skipped by the gate):
    GET  /lab/supply/status          the scenario, the controls live at this level, the collector
    POST /lab/supply/scenario        {"variant", "vendor", "report_only"}  (any subset)
    POST /lab/supply/reset           clear both inboxes
    GET  /lab/supply/csp-reports     what browsers reported
    GET  /lab/supply/violations      what the runtime monitor reported
"""

import os
import re
import secrets
import sys
import threading
from collections import deque
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, g, jsonify, render_template, request

from defenses import pipeline, reloader
from defenses.page_controls import PageControls
from demo_site import hooks

LAB_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if LAB_ROOT not in sys.path:
    sys.path.insert(0, LAB_ROOT)
import labnet  # noqa: E402  (the localhost guard; the collector URL goes through it)

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
VARIANTS = ("beacon", "dynamic", "allowlisted", "firstparty")
VENDORS = ("clean", "compromised", "updated")

_lock = threading.Lock()
STATE = {"variant": os.environ.get("SKIMMER_VARIANT", "beacon"),     # the exfil technique
         "vendor": os.environ.get("VENDOR", "compromised"),            # which file the vendor serves
         "report_only": False}                                         # send the CSP as Report-Only
CSP_REPORTS: deque = deque(maxlen=500)
VIOLATIONS: deque = deque(maxlen=500)

bp = Blueprint("supply", __name__)
_SCRIPT_TAG = re.compile(r"<script(?![^>]*\bnonce=)", re.I)
_PIXEL = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00"
          b"\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")


def _now():
    return datetime.now(timezone.utc).isoformat()


def collector_url():
    """The attacker's sink, through the labnet guard: loopback or the process exits."""
    labnet.require_local_env("COLLECTOR_URL")
    return labnet.target("COLLECTOR_URL", "http://127.0.0.1:5001")


def _asset(name, **subs):
    with open(os.path.join(ASSETS, name), encoding="utf-8") as fh:
        text = fh.read()
    for k, v in subs.items():
        text = text.replace(f"__{k.upper()}__", v)
    return text


def vendor_source():
    """The bytes the vendor include serves right now."""
    vendor = STATE["vendor"]
    if vendor == "clean":
        return _asset("analytics-helper.baseline.js")
    if vendor == "updated":          # a legitimate new release: different bytes, still benign
        return _asset("analytics-helper.baseline.js").replace("2.3.0", "2.4.0")
    return _asset("analytics-helper.js", collector=collector_url(), variant=STATE["variant"])


def bundle_source():
    """The first-party bundle: clean, or the poisoned build when the scenario says so."""
    if STATE["variant"] == "firstparty":
        return _asset("shop-bundle.poisoned.js", collector=collector_url())
    return _asset("shop-bundle.js")


def _js(text):
    r = Response(text, mimetype="application/javascript")
    r.headers["Cache-Control"] = "no-store"
    return r


# ── Response side of the defenses ─────────────────────────────────────────────────────────────

def page_controls():
    """This response's PageControls: the ladder's "page" phase at the current level (memoised per request)."""
    if "supply_page" not in g:
        cfg = current_app.config["LAB"]
        page = PageControls(nonce=secrets.token_urlsafe(16), analytics_origin=collector_url(),
                            report_only=STATE["report_only"])
        ladder = reloader.ladder() if cfg.lab_reload else __import__("defenses.ladder", fromlist=["LADDER"]).LADDER
        pipeline.run("page", page, ladder, cfg.defense_level)
        g.supply_page = page
    return g.supply_page


def _decorate(response):
    if response.mimetype != "text/html" or response.direct_passthrough:
        return response
    page = page_controls()
    if page.csp:
        header = "Content-Security-Policy-Report-Only" if page.report_only else "Content-Security-Policy"
        response.headers[header] = page.csp
    if page.nonce_scripts:
        # The nonce middleware: tag every <script> the store's TEMPLATES rendered. This is what an edge
        # or a framework helper does. It is safe here only because Jinja escapes user input; a response
        # that echoed attacker markup would hand the attacker the nonce too.
        body = _SCRIPT_TAG.sub(f'<script nonce="{page.nonce}"', response.get_data(as_text=True))
        response.set_data(body)
    return response


# ── Routes ────────────────────────────────────────────────────────────────────────────────────

@bp.route("/static/vendor/analytics-helper.js")
def vendor_script():
    return _js(vendor_source())


@bp.route("/static/vendor/pixel.gif")
def vendor_pixel():
    return Response(_PIXEL, mimetype="image/gif")


@bp.route("/static/js/shop-bundle.js")
def shop_bundle():
    return _js(bundle_source())


@bp.route("/lab/supply/scenario", methods=["POST"])
def scenario():
    body = request.get_json(force=True, silent=True) or {}     # force: a plain `curl -d '{...}'` sends no JSON content type
    with _lock:
        if "variant" in body:
            if body["variant"] not in VARIANTS:
                return jsonify(error=f"variant must be one of {VARIANTS}"), 400
            STATE["variant"] = body["variant"]
        if "vendor" in body:
            if body["vendor"] not in VENDORS:
                return jsonify(error=f"vendor must be one of {VENDORS}"), 400
            STATE["vendor"] = body["vendor"]
        if "report_only" in body:
            STATE["report_only"] = bool(body["report_only"])
    return jsonify(ok=True, **STATE)


@bp.route("/lab/supply/status")
def status():
    cfg = current_app.config["LAB"]
    page = PageControls(nonce="<nonce>", analytics_origin=collector_url(), report_only=STATE["report_only"])
    ladder = reloader.ladder() if cfg.lab_reload else __import__("defenses.ladder", fromlist=["LADDER"]).LADDER
    pipeline.run("page", page, ladder, cfg.defense_level)
    return jsonify(level=cfg.defense_level, scenario=dict(STATE), controls=page.describe(), csp=page.csp,
                   collector=collector_url(), csp_reports=len(CSP_REPORTS), violations=len(VIOLATIONS))


@bp.route("/lab/supply/reset", methods=["POST"])
def reset():
    CSP_REPORTS.clear()
    VIOLATIONS.clear()
    return jsonify(ok=True)


@bp.route("/lab/supply/csp-report", methods=["POST"])
def csp_report():
    """The CSP report-uri: browsers POST a violation here (application/csp-report)."""
    raw = request.get_json(force=True, silent=True) or {}
    body = raw.get("csp-report", raw)
    CSP_REPORTS.appendleft({"ts": _now(),
                            "blocked_uri": body.get("blocked-uri") or body.get("blockedURI"),
                            "directive": body.get("violated-directive") or body.get("effectiveDirective"),
                            "disposition": body.get("disposition"),
                            "document_uri": body.get("document-uri") or body.get("documentURI")})
    return "", 204


@bp.route("/lab/supply/csp-reports")
def csp_reports():
    return jsonify(list(CSP_REPORTS))


@bp.route("/lab/supply/violations")
def violations():
    return jsonify(list(VIOLATIONS))


def _on_violation(ctx, body):
    VIOLATIONS.appendleft({"ts": _now(), "method": str(body.get("method"))[:16], "url": str(body.get("url"))[:300],
                           "page": str(body.get("page"))[:300]})
    return {"logged": True}


def init(app):
    app.register_blueprint(bp)
    hooks.slot("head", "supply/head.html")
    hooks.slot("body_end", "supply/body_end.html")
    hooks.telemetry.register("script_violation", _on_violation)
    app.context_processor(lambda: {"supply": page_controls()})
    app.after_request(_decorate)
