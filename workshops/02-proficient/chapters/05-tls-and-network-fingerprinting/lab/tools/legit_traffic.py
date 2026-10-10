"""
Chapter 5 — Legitimate-traffic simulator (Section 5.8, "Measuring both sides")

Every defense in this chapter is measured against these personas as well as
against the bots. A layer that blocks one of them has a cost, even when it
catches every bot.

    persona            client                                     what it represents
    chromium-user      Playwright Chromium (real browser)        Chrome/Edge/Brave desktop users
    firefox-user       Playwright Firefox (real browser)         Firefox desktop users
    webkit-user        Playwright WebKit (real engine, optional) Safari-engine users (see note)
    partner-api        python-requests + partner API key         an integration you signed up
    corporate-proxy    Python TLS with a Chrome UA               Chrome behind a TLS-inspecting proxy
    noscript-firefox   Playwright Firefox, JavaScript disabled   NoScript / Tor "Safest" users

Two of these are *expected* false positives, and the checkpoint reports
them as the cost of the layer rather than as a lab failure:
  - corporate-proxy from Level 2 on. The middlebox re-originates TLS with its
    own stack while the UA stays Chrome. From the server's side it's
    indistinguishable from the Round 1 cipher-tweak bot.
  - noscript-firefox at Level 4. No JS engine, no engine proof.

webkit-user is informational. Playwright's WebKit on Linux/Windows is not
Safari's network stack (it uses libsoup/GLib TLS, not Apple's), so its
JA4 doesn't match the Safari family. That's a real-world false positive too
(GNOME Web, embedded WebKit views). It needs system libraries
(`playwright install-deps webkit`) and is skipped when it can't launch.

Run directly:
    python tools/legit_traffic.py            # all personas
    python tools/legit_traffic.py --no-browser
"""

import os
import ssl
import sys

import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks"))

from _lab import BASE_URL, CA_FILE, CHROME_HEADERS, CHROME_UA  # noqa: E402

# persona -> first DEFENSE_LEVEL at which blocking it is the documented cost
EXPECTED_FALSE_POSITIVE_FROM = {"corporate-proxy": 2, "noscript-firefox": 4}
INFORMATIONAL = {"webkit-user"}

PARTNER_HEADERS = {"User-Agent": "AcmePartnerSync/2.1", "Authorization": "Bearer partner-demo-key",
                   "Accept": "application/json"}
MIDDLEBOX_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES"

BROWSE_JS = """async () => {
  const r = await fetch("/api/products");
  const timing = (r.headers.get("Server-Timing") || "").match(/dur=([0-9.]+)/);
  return {status: r.status, data: await r.json(), score_ms: timing ? parseFloat(timing[1]) : null};
}"""


def _score_ms(response_headers):
    value = response_headers.get("Server-Timing", "") or response_headers.get("server-timing", "")
    try:
        return float(value.split("dur=")[1])
    except (IndexError, ValueError):
        return None


def _row(persona, path, status, data, score_ms=None):
    data = data if isinstance(data, dict) else {}
    return {"persona": persona, "path": path, "status": status, "score_ms": score_ms,
            "reasons": data.get("reasons", []) if status == 403 else []}


def browser_persona(p, persona, engine, java_script=True):
    browser = getattr(p, engine).launch()
    try:
        kwargs = {"ignore_https_errors": True, "java_script_enabled": java_script}
        if engine == "chromium":
            kwargs["user_agent"] = CHROME_UA      # a real user's UA has no "HeadlessChrome"
        page = browser.new_context(**kwargs).new_page()
        if not java_script:
            resp = page.goto(BASE_URL + "/products")
            data = resp.json() if resp.status == 403 else {}
            return [_row(persona, "/products", resp.status, data, _score_ms(resp.headers))]
        resp = page.goto(BASE_URL + "/")
        rows = [_row(persona, "/", resp.status, {}, _score_ms(resp.headers))]
        if resp.status == 200:
            page.wait_for_function("window.__productsStatus !== undefined", timeout=10_000)
            for _ in range(2):
                r = page.evaluate(BROWSE_JS)
                rows.append(_row(persona, "/api/products", r["status"], r["data"], r["score_ms"]))
        return rows
    finally:
        browser.close()


def partner_api():
    rows = []
    with requests.Session() as s:
        for _ in range(3):
            r = s.get(BASE_URL + "/api/products", headers=PARTNER_HEADERS, verify=CA_FILE, timeout=10)
            rows.append(_row("partner-api", "/api/products", r.status_code, r.json(), _score_ms(r.headers)))
    return rows


class MiddleboxTLS(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=CA_FILE)
        ctx.set_ciphers(MIDDLEBOX_CIPHERS)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def corporate_proxy():
    rows = []
    with requests.Session() as s:
        s.mount("https://", MiddleboxTLS())
        for _ in range(3):
            r = s.get(BASE_URL + "/api/products", headers=CHROME_HEADERS, verify=CA_FILE, timeout=10)
            rows.append(_row("corporate-proxy", "/api/products", r.status_code, r.json(), _score_ms(r.headers)))
    return rows


def run(browsers=True):
    """Return one row per request across all personas. Skipped personas get status None."""
    rows = partner_api() + corporate_proxy()
    if not browsers:
        return rows
    from playwright.sync_api import Error as PlaywrightError, sync_playwright
    with sync_playwright() as p:
        for persona, engine, js in [("chromium-user", "chromium", True), ("firefox-user", "firefox", True),
                                    ("webkit-user", "webkit", True), ("noscript-firefox", "firefox", False)]:
            try:
                rows += browser_persona(p, persona, engine, js)
            except PlaywrightError as exc:
                text = str(exc)
                first = ("missing system libraries (playwright install-deps " + engine + ")"
                         if "missing dependencies" in text
                         else next((ln.strip() for ln in text.splitlines() if ln.strip(" ║╔╗╚╝═")), "")[:70])
                rows.append({"persona": persona, "path": "-", "status": None, "score_ms": None,
                             "reasons": [f"skipped: {first}"]})
    return rows


if __name__ == "__main__":
    results = run(browsers="--no-browser" not in sys.argv)
    for persona in dict.fromkeys(r["persona"] for r in results):
        mine = [r for r in results if r["persona"] == persona]
        statuses = [r["status"] for r in mine]
        print(f"{persona:<18} {statuses}")
        for reason in {x for r in mine for x in r["reasons"]}:
            print(f"    - {reason}")
    counted = [r for r in results if r["status"] is not None and r["persona"] not in INFORMATIONAL]
    print(f"\nFalse positives: {sum(r['status'] == 403 for r in counted)}/{len(counted)} requests blocked")
