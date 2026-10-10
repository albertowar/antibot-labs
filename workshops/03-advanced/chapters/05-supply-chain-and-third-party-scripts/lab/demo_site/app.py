"""
W3 Ch5 Demo Store — Supply Chain & Third-Party Scripts

A deliberately small slice of the workshop store: just the pages a client-side
skimmer cares about (a checkout form with a card field, and a login form). It
is the "state" this chapter needs; the full Redis/PostgreSQL store from W2 adds
nothing to a lesson about code running in the *browser*, so this runs with no
Docker and no database — violation logs live in memory and clear on restart.

The scenario each round is a vendor/supply-chain compromise that is ALREADY in
place: the page loads a third-party include (`/static/vendor/analytics-helper.js`)
that, besides real analytics, carries a lab skimmer. Students do not write the
skimmer; they add the DEFENSE each round and watch the exfil stop.

Everything is driven by environment variables so the checkpoint can set a round
up deterministically:

  CSP_MODE          off | report-only | enforce | strict      (default: off)
                    "enforce" is the common host-allowlist policy (with the
                    real-world 'unsafe-inline' + permissive img-src mistakes).
                    "strict" is nonce + strict-dynamic, the modern policy.
  SRI               off | on                                   (default: off)
                    When on, the vendor <script> carries an integrity hash
                    pinned to the KNOWN-GOOD baseline. A swapped file is refused.
  MONITOR           off | on                                   (default: off)
                    When on, runtime-monitor.js loads first and wraps
                    fetch / XHR / sendBeacon.
  SKIMMER_VARIANT   beacon | dynamic | allowlisted | firstparty (default: beacon)
                    Which exfil technique the compromise uses (maps to rounds).
  COLLECTOR_URL     the local attacker sink   (default: http://127.0.0.1:5001)
  PORT              (default: 5000)

Run:
  CSP_MODE=off python app.py
"""

import base64
import hashlib
import os
import secrets
from collections import deque
from datetime import datetime, timezone

from flask import (Flask, Response, g, jsonify, render_template, request,
                   send_from_directory)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

CSP_MODE = os.environ.get("CSP_MODE", "off")            # off|report-only|enforce|strict
SRI = os.environ.get("SRI", "off") == "on"
MONITOR = os.environ.get("MONITOR", "off") == "on"
SKIMMER_VARIANT = os.environ.get("SKIMMER_VARIANT", "beacon")
VENDOR = os.environ.get("VENDOR", "compromised")      # clean | compromised
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:5001")
# A third-party origin the store legitimately talks to (analytics / beacons).
# When set, strict CSP must allow it in connect-src/img-src — which is exactly
# the gap a poisoned first-party bundle rides in Round 4.
TRUSTED_ANALYTICS = os.environ.get("TRUSTED_ANALYTICS", "")

HERE = os.path.dirname(__file__)
VENDOR_DIR = os.path.join(HERE, "static", "vendor")

# In-memory, bounded violation logs. Restart clears them.
_csp_violations: deque = deque(maxlen=200)
_script_violations: deque = deque(maxlen=200)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sri_for(filename: str) -> str:
    """SHA-384 SRI value for a file in the vendor dir, pinned to the baseline.

    SRI is a promise about a *specific* known-good file. We pin it to the
    benign baseline (`*.baseline.js`); the served file may have been swapped by
    the "vendor compromise", in which case the hash will not match and the
    browser refuses to run it. That is exactly the point.
    """
    baseline = filename.replace(".js", ".baseline.js")
    path = os.path.join(VENDOR_DIR, baseline)
    if not os.path.exists(path):
        path = os.path.join(VENDOR_DIR, filename)
    with open(path, "rb") as fh:
        digest = hashlib.sha384(fh.read()).digest()
    return "sha384-" + base64.b64encode(digest).decode()


# ── CSP policy strings ─────────────────────────────────────────────────────────
# Kept in one place so students can read exactly what each round changes. The
# standalone copy in defenses/csp_policies.py is the studied version.

def csp_policy(nonce: str) -> str:
    if CSP_MODE in ("report-only", "enforce"):
        # The *weak* host-allowlist policy. Note the two realistic mistakes:
        #   - 'unsafe-inline' in script-src (added so existing inline snippets
        #     keep working) — this is what lets an injected inline script run.
        #   - a permissive img-src (http:/https:) — a pixel can exfil through it
        #     even when connect-src is locked to 'self'.
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https:; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: http: https:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "report-uri /csp-report"
        )
    if CSP_MODE == "strict":
        # The modern policy: no allowlist to bypass. Only nonced scripts run,
        # and strict-dynamic lets them load the libraries they trust. The exfil
        # channels (connect-src, img-src) are closed, and object/base are shut.
        # A real store usually must allow ONE third-party beacon origin here;
        # TRUSTED_ANALYTICS models that, and Round 4 shows the cost.
        extra = f" {TRUSTED_ANALYTICS}" if TRUSTED_ANALYTICS else ""
        return (
            f"default-src 'self'; "
            f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"style-src 'self'; "
            f"img-src 'self' data:{extra}; "
            f"connect-src 'self'{extra}; "
            f"font-src 'self'; "
            f"frame-ancestors 'self'; "
            f"require-trusted-types-for 'script'; "
            f"report-uri /csp-report"
        )
    return ""


@app.before_request
def make_nonce():
    g.nonce = secrets.token_urlsafe(16)


@app.after_request
def add_security_headers(response: Response) -> Response:
    policy = csp_policy(getattr(g, "nonce", ""))
    if policy:
        header = (
            "Content-Security-Policy-Report-Only"
            if CSP_MODE == "report-only"
            else "Content-Security-Policy"
        )
        response.headers[header] = policy
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def _page_context():
    vendor_sri = _sri_for("analytics-helper.js") if SRI else None
    return {
        "csp_mode": CSP_MODE,
        "sri": SRI,
        "monitor": MONITOR,
        "variant": SKIMMER_VARIANT,
        "collector": COLLECTOR_URL,
        "nonce": getattr(g, "nonce", ""),
        "vendor_sri": vendor_sri,
    }


@app.route("/static/vendor/analytics-helper.js")
def vendor_script():
    """Serve the clean baseline or the compromised file, per the VENDOR env.

    This is how the "vendor swapped the file" step is staged: build your SRI /
    inventory baseline while VENDOR=clean, then restart with VENDOR=compromised
    (the default) and watch the change-monitor and SRI react.
    """
    name = "analytics-helper.baseline.js" if VENDOR == "clean" else "analytics-helper.js"
    resp = send_from_directory(VENDOR_DIR, name)
    resp.headers["Content-Type"] = "application/javascript"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ── Pages ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", **_page_context())


@app.route("/product/<sku>")
def product(sku):
    return render_template("product.html", sku=sku, **_page_context())


@app.route("/checkout", methods=["GET"])
def checkout_form():
    return render_template("checkout.html", **_page_context())


@app.route("/checkout", methods=["POST"])
def checkout_submit():
    # The real store would charge the card here. We only confirm receipt so the
    # page's own (legitimate) submission still completes — a skimmer is an
    # EXTRA, invisible connection running alongside this one.
    return jsonify({"ok": True, "message": "Order received (demo — no real charge)"}), 200


@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html", **_page_context())


@app.route("/login", methods=["POST"])
def login_submit():
    return jsonify({"ok": True, "message": "Login accepted (demo)"}), 200


# ── Report collectors (the defender's inbox) ──────────────────────────────────

@app.route("/csp-report", methods=["POST"])
def csp_report():
    """Browsers POST here on a CSP violation (the report-uri directive)."""
    report = request.get_json(force=True, silent=True) or {}
    body = report.get("csp-report", report)
    _csp_violations.appendleft({
        "ts": _now(),
        "blocked_uri": body.get("blocked-uri") or body.get("blockedURI"),
        "violated_directive": body.get("violated-directive") or body.get("effectiveDirective"),
        "document_uri": body.get("document-uri") or body.get("documentURI"),
        "raw": body,
    })
    return "", 204


@app.route("/csp-report/log")
def csp_report_log():
    return jsonify(list(_csp_violations))


@app.route("/api/script-violation", methods=["POST"])
def script_violation():
    """runtime-monitor.js POSTs here when a script calls out to a bad origin."""
    data = request.get_json(force=True, silent=True) or {}
    _script_violations.appendleft({
        "ts": _now(),
        "method": data.get("method"),
        "url": data.get("url"),
        "page": data.get("page"),
    })
    return "", 204


@app.route("/api/script-violation/log")
def script_violation_log():
    return jsonify(list(_script_violations))


@app.route("/status")
def status():
    """Lets tools read how the server is configured without guessing."""
    return jsonify({
        "chapter": "W3 Ch5",
        "csp_mode": CSP_MODE,
        "sri": SRI,
        "monitor": MONITOR,
        "skimmer_variant": SKIMMER_VARIANT,
        "vendor": VENDOR,
        "trusted_analytics": TRUSTED_ANALYTICS,
        "collector_url": COLLECTOR_URL,
        "csp_violations": len(_csp_violations),
        "script_violations": len(_script_violations),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"Demo store on http://127.0.0.1:{port}  "
          f"(CSP_MODE={CSP_MODE} SRI={'on' if SRI else 'off'} "
          f"MONITOR={'on' if MONITOR else 'off'} VARIANT={SKIMMER_VARIANT} VENDOR={VENDOR})")
    app.run(host="127.0.0.1", port=port, debug=False)
