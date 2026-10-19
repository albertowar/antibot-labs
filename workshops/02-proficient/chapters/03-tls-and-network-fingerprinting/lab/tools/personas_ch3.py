"""
W2 Ch3's shoppers: the other half of every TLS measurement.

Two groups, because a TLS check needs real handshakes and the store's 40 shoppers are Python.

1. The 40 starter shoppers (tools/population.py) run the `tls_browse` scenario. They cannot speak
   a browser's TLS, so each one sends the fingerprint of the browser it plays as a CLAIMED JA4
   (`X-Lab-JA4`, which the contract allows until a TLS edge measures one), and, where a browser
   would run the page's script, a PAGE_HOOK posts the engine proof the script would post. They
   carry the false-positive accounting of the whole chapter: `no_js` is the one persona a layer may
   hurt (Round 4), and it is the real cost of demanding a JavaScript engine.

2. The real clients (`run_real_clients`) go through the TLS edge with their own handshakes, so
   every layer judges a measured fingerprint:

     partner_api       python-requests with a partner key        an integration you signed up
     corporate_proxy   Python TLS, Chrome UA                     Chrome behind a TLS-inspecting proxy
     chromium_user     Playwright Chromium (a real browser)      Chrome/Edge/Brave desktop users
     firefox_user      Playwright Firefox (a real browser)       Firefox desktop users
     webkit_user       Playwright WebKit, optional               informational: on Linux/Windows it is
                       not Safari's network stack (libsoup / GLib TLS, not Apple's), so its JA4
                       matches no Safari family. A real false positive too (GNOME Web, embedded
                       WebKit views). Skipped when the engine or its system libraries are missing.

   `corporate_proxy` is a documented false positive from Round 2 on: the middlebox re-originates
   TLS with its own stack while the UA stays Chrome, and from the store's side that is
   indistinguishable from Round 1's cipher-tweak bot.
"""

import os
import re
import ssl
import sys

import requests
from requests.adapters import HTTPAdapter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import labclient  # noqa: E402
import population  # noqa: E402

# The first DEFENSE_LEVEL at which a real client is a documented false positive.
EXPECTED_FALSE_POSITIVE_FROM = {"corporate_proxy": 2}
INFORMATIONAL = {"webkit_user"}

# The fingerprint each simulated browser would present (a+b are the verified browser families in
# defenses/known_fingerprints.json; c is a placeholder, nothing keys on it).
CLAIMED_JA4 = {
    "chrome": "t13d1516h2_8daaf6152771_806a8c22fdea",
    "firefox": "t13d1517h2_8daaf6152771_a87ad97598a9",
    "safari": "t13d2013h2_a09f3c656075_7f0f34a4126d",
}
# (TypeError message, eval source length) per JS engine: what tls_engine.js would read there.
ENGINE_SIGNALS = {
    "chrome": ("Cannot read properties of null (reading 'f')", 33),
    "firefox": ("can't access property \"f\" of null", 37),
    "safari": ("null is not an object (evaluating 'null.f')", 33),
}
NONCE = re.compile(r'data-nonce="([^"]+)"')
NO_JS = "no_js"


def scenario_tls_browse(p, client, rng):
    """The starter's browse scenario, with the browser's claimed JA4 on every request."""
    client.ja4 = CLAIMED_JA4[p.browser[0]]
    return population.scenario_browse(p, client, rng)


population.SCENARIOS["tls_browse"] = scenario_tls_browse


def engine_hook(p, client, r):
    """What tls_engine.js does in a browser: read the nonce off the page, post the engine signals once."""
    if not p.js or p.result.get("engine_posted") or r.status_code != 200:
        return None
    m = NONCE.search(r.text)
    if not m:
        return None
    message, length = ENGINE_SIGNALS[p.browser[0]]
    ua = dict(browsers.headers_for(p.browser, "post", population.BASE_URL, population.BASE_URL + "/")).get("User-Agent", "")
    client.post("/api/telemetry", headers=[("User-Agent", ua), ("Content-Type", "application/json")],
                json={"kind": "engine", "nonce": m.group(1), "error_message": message, "eval_length": length})
    p.result["engine_posted"] = True
    return None


population.PAGE_HOOKS.append(engine_hook)


def summarize(results):
    """{persona: (people, refused)} over the 40 shoppers."""
    out = {}
    for r in results:
        users, blocked = out.get(r["persona"], (0, 0))
        out[r["persona"]] = (users + 1, blocked + int(r.get("outcome") == "blocked"))
    return out


# --- The real clients, through the TLS edge --------------------------------------------------

MIDDLEBOX_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES"
PARTNER_HEADERS = {"User-Agent": "AcmePartnerSync/2.1", "Authorization": "Bearer partner-demo-key", "Accept": "application/json"}
CHROME_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")

BROWSE_JS = """async () => {
  const out = [];
  for (const path of ["/api/products", "/api/products", "/products"]) {
    const r = await fetch(path);
    out.push({path, status: r.status, signals: r.headers.get("x-lab-signals") || ""});
  }
  return out;
}"""


def _row(persona, path, status, signals=""):
    return {"persona": persona, "path": path, "status": status, "signals": signals}


class MiddleboxTLS(HTTPAdapter):
    """urllib3 adapter whose ClientHello is a TLS-inspecting proxy's, not the browser's."""

    def __init__(self, ca_file, **kw):
        self.ca_file = ca_file
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=self.ca_file)
        ctx.set_ciphers(MIDDLEBOX_CIPHERS)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _library_persona(persona, pool, edge, ca_file, headers, adapter=None):
    rows = []
    lab = {"X-Lab-Client-IP": labclient.world_pool(pool)[2], "X-Lab-Actor": f"human:{persona}:00"}
    with requests.Session() as s:
        if adapter is not None:
            s.mount("https://", adapter)
        for _ in range(3):
            r = s.get(edge + "/api/products", headers={**headers, **lab}, verify=ca_file, timeout=20)
            rows.append(_row(persona, "/api/products", r.status_code, r.headers.get("X-Lab-Signals", "")))
    return rows


def _browser_persona(p, persona, engine, edge):
    browser = getattr(p, engine).launch()
    try:
        kw = {"ignore_https_errors": True}
        if engine == "chromium":
            kw["user_agent"] = CHROME_UA            # a real user's UA has no "HeadlessChrome"
        context = labclient.browser_context(browser, f"human:{persona}:00", ip=labclient.world_pool("home_fiber")[2], **kw)
        page = context.new_page()
        resp = page.goto(edge + "/")
        rows = [_row(persona, "/", resp.status, resp.headers.get("x-lab-signals", ""))]
        if resp.status == 200:
            try:
                page.wait_for_function("sessionStorage.getItem('tls_engine') === '1'", timeout=10_000)
            except Exception:
                pass
            rows += [_row(persona, r["path"], r["status"], r["signals"]) for r in page.evaluate(BROWSE_JS)]
        return rows
    finally:
        browser.close()


def run_real_clients(edge, ca_file, with_browsers=True):
    """One list of rows (persona, path, status, signals); a persona that cannot run gets status None."""
    rows = _library_persona("partner_api", "cloud_vm", edge, ca_file, PARTNER_HEADERS)
    chrome_headers = {"User-Agent": CHROME_UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
                      "Accept-Encoding": "gzip, deflate, br, zstd"}
    rows += _library_persona("corporate_proxy", "corporate", edge, ca_file, chrome_headers, MiddleboxTLS(ca_file))
    if not with_browsers:
        return rows
    from playwright.sync_api import Error as PlaywrightError, sync_playwright
    with sync_playwright() as p:
        for persona, engine in (("chromium_user", "chromium"), ("firefox_user", "firefox"), ("webkit_user", "webkit")):
            try:
                rows += _browser_persona(p, persona, engine, edge)
            except PlaywrightError as exc:
                text = str(exc)
                first = ("missing system libraries (playwright install-deps " + engine + ")" if "missing dependencies" in text
                         else "not installed (python -m playwright install " + engine + ")" if "Executable doesn't exist" in text
                         else next((ln.strip() for ln in text.splitlines() if ln.strip(" ║╔╗╚╝═")), "")[:70])
                rows.append(_row(persona, "-", None, f"skipped: {first}"))
    return rows


def judge(rows, level):
    """(ok, message): no real client blocked except the documented false positives, and those DO show."""
    problems, report = [], []
    for persona in dict.fromkeys(r["persona"] for r in rows):
        mine = [r for r in rows if r["persona"] == persona]
        if mine[0]["status"] is None:
            report.append((persona, "skipped", mine[0]["signals"]))
            continue
        blocked = [r for r in mine if r["status"] == 403]
        documented = persona in EXPECTED_FALSE_POSITIVE_FROM and level >= EXPECTED_FALSE_POSITIVE_FROM[persona]
        if persona in INFORMATIONAL:
            report.append((persona, f"{len(blocked)}/{len(mine)} blocked (informational)", sorted({r['signals'] for r in blocked})))
            continue
        if blocked and not documented:
            problems.append(f"{persona}: {len(blocked)}/{len(mine)} requests blocked ({sorted({r['signals'] for r in blocked})})")
        if documented and not blocked:
            problems.append(f"{persona}: should be a documented false positive at level {level}, but nothing blocked it")
        report.append((persona, f"{len(blocked)}/{len(mine)} blocked" + (" (documented false positive)" if documented else ""),
                       sorted({r["signals"] for r in blocked})))
    return problems, report
