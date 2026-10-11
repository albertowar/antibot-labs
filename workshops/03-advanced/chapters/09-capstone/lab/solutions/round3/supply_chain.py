"""
Capstone L7 — supply chain: CSP, SRI, runtime fetch monitor (W3 Ch5)

The skimmer in attacks/round3_skimmer.py does what a real one does: it hides in
a third-party script (static/analytics-helper.js), reads the checkout fields,
and POSTs them to an attacker origin in parallel with the honest submit. The
TLS to your own server is intact, so nothing upstream sees it. Three browser-
level controls close it, in order of strength:

    SRI   pins the hash of each <script> you include yourself. It catches a
          tampered file on a CDN, but NOT a script injected at runtime by
          another script — which is exactly how a skimmer spreads once it has a
          foothold. First line, not the last.
    CSP   connect-src tells the browser which origins a page may talk to. Set it
          to 'self' and the skimmer's cross-origin POST is refused by the
          browser, and a violation report is sent to /api/script-violation.
          This is the control that actually stops exfiltration.
    runtime monitor (static/runtime_monitor.js) wraps fetch and sendBeacon to
          alert on unexpected destinations. It is detection, not enforcement: a
          script that loads before it can unwrap it. CSP is the enforcement.

score_violations() turns reports into risk points so a page that tried to
exfiltrate also raises the session's score for the other layers.
"""

import json

EXFIL_ORIGIN = "https://collector.evil.example"   # where the lab skimmer tries to POST
SELF_ORIGIN = "https://localhost:8443"

# --- TODO (Round 3): write the enforcing CSP --------------------------------
# The starter policy is report-only and allows any origin, so the skimmer's
# exfil succeeds and you only get a report. Turn CSP to enforce and lock
# connect-src to the origins the page legitimately talks to (its own). Do NOT
# add the collector origin. Keep 'self' for scripts plus the per-request nonce.
# Reference solution: solutions/round3/supply_chain.py.
CSP_ENFORCE = True                                  # SOLUTION (Round 3): enforce, not report-only
CONNECT_SRC = ["'self'"]                            # SOLUTION (Round 3): only our own origin; the collector is refused
# ----------------------------------------------------------------------------

SCRIPT_SRC_BASE = ["'self'"]
VIOLATION_POINTS = 55


def csp_header(nonce):
    """(header_name, value). Report-only until you turn CSP_ENFORCE on."""
    directives = [
        "default-src 'self'",
        "script-src " + " ".join(SCRIPT_SRC_BASE + [f"'nonce-{nonce}'"]),
        "connect-src " + " ".join(CONNECT_SRC),
        "report-uri /api/script-violation",
    ]
    name = "Content-Security-Policy" if CSP_ENFORCE else "Content-Security-Policy-Report-Only"
    return name, "; ".join(directives)


def _host(origin):
    o = origin.split("://", 1)[-1]
    return o.split("/", 1)[0]


def exfil_allowed(origin):
    """Would the current connect-src let the page POST to `origin`? The browser
    decides this; the lab checks it deterministically so a round can be measured
    without driving a real browser. 'self' matches only SELF_ORIGIN's host."""
    for src in CONNECT_SRC:
        if src in ("*", "https:") and origin.startswith("https"):
            return True
        if src == "'self'" and _host(origin) == _host(SELF_ORIGIN):
            return True
        if src.startswith("http") and _host(src) == _host(origin):
            return True
    return False


# --- SRI --------------------------------------------------------------------
import base64
import hashlib


def sri_hash(body):
    digest = hashlib.sha384(body.encode() if isinstance(body, str) else body).digest()
    return "sha384-" + base64.b64encode(digest).decode()


def sri_mismatch(expected, body):
    return expected and sri_hash(body) != expected


# --- violation scoring ------------------------------------------------------
def record_violation(store, sid, report):
    store.rpush(f"csp:viol:{sid}", json.dumps(report))
    store.expire(f"csp:viol:{sid}", 1800)
    store.incr("csp:viol:count")


def score_violations(store, sid):
    if not sid:
        return 0, []
    reports = store.lrange(f"csp:viol:{sid}", 0, -1)
    if not reports:
        return 0, []
    blocked = {json.loads(r).get("blocked-uri", "?") for r in reports}
    return VIOLATION_POINTS, [f"page attempted {len(reports)} blocked connection(s) to "
                              f"{', '.join(sorted(blocked))[:80]}: possible skimmer"]


if __name__ == '__main__':
    name, value = csp_header("abc123")
    print("starter:", name)
    assert name.endswith("Report-Only"), "starter must be report-only"
    assert exfil_allowed(EXFIL_ORIGIN), "starter connect-src must let the skimmer out (so the attack works at L<7)"
    # reference solution:
    globals().update(CSP_ENFORCE=True, CONNECT_SRC=["'self'"])
    name, value = csp_header("abc123")
    assert name == "Content-Security-Policy", name
    assert not exfil_allowed(EXFIL_ORIGIN), "solution must block the collector origin"
    assert exfil_allowed(SELF_ORIGIN), "solution must still allow same-origin"
    assert sri_mismatch(sri_hash("good"), "tampered")
    print("supply_chain self-test OK (solution enforces + blocks exfil, allows self, SRI catches tamper)")
