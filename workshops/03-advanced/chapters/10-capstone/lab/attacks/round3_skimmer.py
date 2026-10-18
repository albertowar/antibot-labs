"""
Round 3 attack: a third-party form skimmer (W3 Ch5). Level 7 stops it; below it the exfil lands.

A skimmer rides in a trusted third-party script (static/js/analytics-helper.js, a vendor tag on every page), reads
the checkout or login fields and POSTs them to an attacker origin in parallel with the honest submit
(static/js/skimmer.js is the payload). The user sees nothing, and the TLS to the real server is intact, so nothing on
the server side notices the extra connection. Only the *browser* can refuse it, so this attack measures the defense
the way a browser would decide it:

  1. it loads /login, finds the vendor tag and reads the Content-Security-Policy the page ships
  2. it asks "would that policy let the skimmer POST to the collector?" (a Report-Only policy blocks nothing)
  3. below level 7 there is no policy: the exfil succeeds. At level 7, once connect-src is locked to 'self' (the
     Round 3 TODO in defenses/supply_chain.py), the browser would refuse it, and it would send the violation report
     that the attack posts to /api/script-violation, so the session's level 7 score rises
  4. a real-browser proof (headless Chromium) injects the skimmer into the page and watches the console: a CSP
     refusal is a "Content Security Policy" error. Skipped, and said so, when Playwright's browser is not installed.

The collector is fictional and is never contacted: the browser context aborts every request that leaves this machine.

    python attacks/round3_skimmer.py
"""

import sys

from _api import BASE_URL, Bot, Cost, emit, lab_headers, rng_for, say, verdict

COLLECTOR_ORIGIN = "https://collector.evil.example"
COLLECTOR = COLLECTOR_ORIGIN + "/collect"


def would_exfil(headers):
    """Mirror the browser's connect-src check: would a POST to COLLECTOR be allowed by the page's enforced policy?"""
    csp = headers.get("Content-Security-Policy")                     # Report-Only never blocks, so only this one counts
    if not csp:
        return True
    sources = next((d.split()[1:] for d in csp.split(";") if d.split() and d.split()[0].lower() == "connect-src"), None)
    if sources is None:
        sources = next((d.split()[1:] for d in csp.split(";") if d.split() and d.split()[0].lower() == "default-src"), [])
    host = COLLECTOR.split("://", 1)[-1].split("/", 1)[0]
    return any(src in ("*", "https:") or (src.startswith("http") and src.split("://", 1)[-1].split("/", 1)[0] == host)
               for src in sources)


CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
# Headless Chromium names itself in the Client Hints; level 1 refuses that (it is Round 0's lesson). The browser here
# plays a CUSTOMER of the store, whose page the skimmer lives on, so it is given a customer's Chrome identity.
CHROME_HINTS = {"Sec-CH-UA": '"Google Chrome";v="153", "Chromium";v="153", "Not_A Brand";v="8"',
                "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Linux"',
                "X-Lab-JA4": "t13d1516h2_8daaf6152771_806a8c22fdea"}


def browser_proof():
    """
    Drive Chromium as the victim: load /login, let the compromised vendor tag's payload (skimmer.js) run, type into the
    form, and watch two things: did CSP refuse the exfil (a "Content Security Policy" console error), and did the
    page's own same-origin telemetry still get through (the policy must not break the store). None when it cannot run.
    """
    try:
        from playwright.sync_api import sync_playwright
        import labclient
        ip = labclient.world_pool("home_broadband")[7]
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = labclient.browser_context(browser, "bot:round3_skimmer_proof", ip=ip, user_agent=CHROME_UA)
            ctx.set_extra_http_headers(dict(CHROME_HINTS, **{"X-Lab-Client-IP": ip, "X-Lab-Actor": "bot:round3_skimmer_proof"}))
            page = ctx.new_page()
            refused = []
            page.on("console", lambda m: refused.append(m.text) if "Content Security Policy" in m.text and "collector" in m.text else None)
            page.goto(BASE_URL + "/login", timeout=15000)
            page.add_script_tag(url=BASE_URL + "/static/js/skimmer.js")   # what the compromised vendor tag would do
            page.fill("#login-form input[name=email]", "victim@example.test")
            page.dispatch_event("#login-form input[name=email]", "change")   # fill() sends only `input`; the skimmer listens for `change`
            page.wait_for_timeout(1200)
            browser.close()
        rows = labclient.admin("GET", "/lab/decisions", params={"actor": "bot:round3_skimmer_proof", "path": "/api/telemetry"})
        return {"csp_refused": bool(refused), "telemetry_ok": any(r["outcome"] == "served" for r in rows["items"])}
    except Exception as exc:                                          # no browser installed, or it would not start
        print(f"  browser proof skipped: {type(exc).__name__}: {str(exc)[:80]}", file=sys.stderr)
        return None


def skim(rng):
    bot = Bot("bot:round3_skimmer", rng)
    r = bot.get("/login")                                              # a page with the vendor tag and the form fields
    loaded = "/static/js/analytics-helper.js" in r.text
    enforced = r.headers.get("Content-Security-Policy")
    report_only = r.headers.get("Content-Security-Policy-Report-Only")
    exfil = would_exfil(r.headers)
    if not exfil:                                                      # what the browser would send when it refuses
        bot.post("/api/script-violation", json={"csp-report": {"blocked-uri": COLLECTOR, "violated-directive": "connect-src"}})
    res = verdict(r)
    res.update(status="reserved" if exfil else "blocked", vendor_tag=loaded,
               policy="enforced" if enforced else "report-only" if report_only else "none",
               signals=[f"exfil to {COLLECTOR_ORIGIN} " + ("would be allowed" if exfil else "refused by connect-src")])
    return res


if __name__ == "__main__":
    print("=== Round 3: form skimmer ===")
    with Cost() as cost:
        res = skim(rng_for("round3"))
        proof = browser_proof()
    say("form_skimmer", res, f"vendor tag loaded: {res['vendor_tag']}, policy: {res['policy']}")
    if proof is None:
        note = "skipped"
    else:
        note = ("CSP refused the exfil in Chromium" if proof["csp_refused"] else "NOT refused by CSP in Chromium") + \
               (", same-origin telemetry still worked" if proof["telemetry_ok"] else ", but the page's own telemetry did NOT get through")
    print(f"  browser proof: {note}")
    emit("round3_skimmer", [res], cost, policy=res["policy"], browser_proof=note)
