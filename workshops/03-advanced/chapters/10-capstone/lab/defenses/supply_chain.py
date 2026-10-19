"""
Level 7 (Round 3): supply chain. CSP, SRI and a runtime fetch monitor (W3 Ch7).

The skimmer rides in a trusted third-party script (static/js/analytics-helper.js, a vendor tag the store includes
on every page), reads the checkout and login fields, and POSTs them to an attacker origin in parallel with the
honest submit (static/js/skimmer.js is the payload). The TLS to your own server is intact, so nothing upstream sees
it. Three browser-level controls close it, in order of strength:

    SRI      pins the hash of each <script> you include yourself. It catches a tampered file on a CDN, but NOT a
             script injected at runtime by another script, which is exactly how a skimmer spreads once it has a
             foothold. First line, not the last.
    CSP      connect-src tells the browser which origins a page may talk to. Set it to 'self' and the skimmer's
             cross-origin POST is refused by the browser, and a violation report is sent to /api/script-violation.
             This is the control that actually stops exfiltration.
    runtime  static/js/runtime_monitor.js wraps fetch and sendBeacon and reports calls to unexpected destinations.
             It is detection, not enforcement: a script that loads before it can unwrap it. CSP is the enforcement.

demo_site/ext/supply9.py sends the header (from csp_header() below, at level 7 and above) and keeps the report sink.
This module owns the policy and the check that turns a session's violation reports into risk points, so a page that
tried to exfiltrate also raises the session's score for the buy.

Simplification, said plainly: the store's templates carry inline scripts (the sensor, the collectors), so the ext
tags every <script> in a response with the per-response nonce. That is what an edge or a framework helper does, and
it is safe only because Jinja escapes user input: a response that echoed attacker markup would hand the attacker the
nonce too. W3 Ch7 is where the nonce, `strict-dynamic` and Trusted Types are taught properly.
"""

import base64
import hashlib
import json
from urllib.parse import urlsplit

from . import policy
from .pipeline import Check, Signal

EXFIL_ORIGIN = "https://collector.evil.example"        # where the lab skimmer tries to POST (never contacted)

# --- TODO (Round 3): write the enforcing CSP ----------------------------------------------------------
# The starter policy is report-only and allows any HTTPS origin, so the skimmer's exfil succeeds and you only get
# a report. Turn CSP to enforce and lock connect-src to the origins the page legitimately talks to (its own). Do
# NOT add the collector origin. The reference solution is in solutions/round3/defenses/supply_chain.py.
CSP_ENFORCE = False                                 # TODO (Round 3): True
CONNECT_SRC = ["'self'", "https:"]                  # TODO (Round 3): ["'self'"]
# ------------------------------------------------------------------------------------------------------

SCRIPT_SRC_BASE = ["'self'"]


def csp_header(nonce):
    """(header name, value). Report-only until you turn CSP_ENFORCE on."""
    directives = [
        "default-src 'self'",
        "script-src " + " ".join(SCRIPT_SRC_BASE + [f"'nonce-{nonce}'"]),
        "connect-src " + " ".join(CONNECT_SRC),
        # What the first report-only week would have told you was about to break (W2's sensor reads the browser's
        # identity again from a blob: Worker; the drop page has inline styles):
        "worker-src 'self' blob:",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "report-uri /api/script-violation",
    ]
    name = "Content-Security-Policy" if CSP_ENFORCE else "Content-Security-Policy-Report-Only"
    return name, "; ".join(directives)


def _host(origin):
    return urlsplit(origin if "://" in origin else f"//{origin}").netloc


def exfil_allowed(origin, self_origin):
    """Would the current connect-src let the page POST to `origin`? The browser decides this; the lab asks the same
    question deterministically so a round can be measured without a browser. 'self' matches only self_origin's host."""
    for src in CONNECT_SRC:
        if src in ("*", "https:") and origin.startswith("https"):
            return True
        if src == "'self'" and _host(origin) == _host(self_origin):
            return True
        if src.startswith("http") and _host(src) == _host(origin):
            return True
    return False


# --- SRI ----------------------------------------------------------------------------------------------

def sri_hash(body):
    digest = hashlib.sha384(body.encode() if isinstance(body, str) else body).digest()
    return "sha384-" + base64.b64encode(digest).decode()


def sri_mismatch(expected, body):
    return bool(expected) and sri_hash(body) != expected


# --- violation scoring --------------------------------------------------------------------------------

def record_violation(redis, sid, report):
    key = f"lab:csp:viol:{sid}"
    redis.rpush(key, json.dumps(report))
    redis.ltrim(key, -50, -1)
    redis.expire(key, 1800)
    redis.incr("lab:csp:count")


def score_violations(redis, sid):
    reports = redis.lrange(f"lab:csp:viol:{sid}", 0, -1) if sid else []
    if not reports:
        return []
    blocked = {json.loads(r).get("blocked-uri", "?") for r in reports}
    return [Signal("supply_chain", "violation", policy.VIOLATION_POINTS,
                   f"page attempted {len(reports)} blocked connection(s) to {', '.join(sorted(blocked))[:80]}: possible skimmer")]


def _check(ctx):
    return score_violations(ctx.redis, ctx.session.sid)


CHECK = Check("supply_chain", _check, phases=("action:drop_buy",))


if __name__ == "__main__":
    own = "http://127.0.0.1:5000"
    name, value = csp_header("abc123")
    print("starter:", name)
    assert name.endswith("Report-Only"), "the starter must be report-only"
    assert exfil_allowed(EXFIL_ORIGIN, own), "the starter's connect-src must let the skimmer out (so the attack works below level 7)"
    globals().update(CSP_ENFORCE=True, CONNECT_SRC=["'self'"])      # the reference solution
    name, value = csp_header("abc123")
    assert name == "Content-Security-Policy", name
    assert not exfil_allowed(EXFIL_ORIGIN, own), "the solution must block the collector origin"
    assert exfil_allowed(own, own), "the solution must still allow the same origin"
    assert sri_mismatch(sri_hash("good"), "tampered")
    print("supply_chain self-test OK (the solution enforces, blocks the exfil, allows the same origin; SRI catches a tampered file)")
