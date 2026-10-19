"""
Round 4 attack: stop pretending, drive a real browser.

Objective: beat the JS engine proof. A real Chromium has the real ClientHello, the real HTTP/2
preface and a real V8, so it passes every layer in this chapter. The only changes are a UA without
"HeadlessChrome" (W1 Ch4 would catch that) and scraping with in-page fetch().

Gotcha: Playwright's `page.request` / `context.request` API does NOT use the browser's network
stack. It sends from Node.js with Node's TLS, which has a completely different JA4. Bots that mix
the two leak that fingerprint (Round 0 shows it).

The cost moves to the attacker: compare this script's requests per second and memory with Round 3
(tools/checkpoint.py prints the time). Catching it is the job of W2 Ch1 (automation artifacts) and
W2 Ch5 (behavior).

Expected results:
  - DEFENSE_LEVEL=4 -> 200 on every request

Run:
    python attacks/round4_playwright_chromium.py
"""

from playwright.sync_api import sync_playwright

from _common import CHROME_UA, EDGE_URL, PATH, REQUESTS, bot_ip, finish, labclient

SCRAPE_JS = """async ([path, n]) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = await fetch(path);
    out.push({status: r.status, signals: r.headers.get("x-lab-signals") || "", score: r.headers.get("x-lab-score") || "",
              n: r.ok ? (await r.json()).items.length : 0});
  }
  return out;
}"""


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = labclient.browser_context(browser, "bot:playwright_chromium", ip=bot_ip(),
                                            user_agent=CHROME_UA, ignore_https_errors=True)
        page = context.new_page()
        page.goto(EDGE_URL + "/")
        try:        # the page's script posts the engine proof once; wait for it
            page.wait_for_function("sessionStorage.getItem('tls_engine') === '1'", timeout=10_000)
        except Exception:
            pass
        rows = page.evaluate(SCRAPE_JS, [PATH, REQUESTS])
        browser.close()
    return [{"status": r["status"], "signals": r["signals"], "score": r["score"], "ok": r["status"] == 200, "n": r["n"]}
            for r in rows]


if __name__ == "__main__":
    print("=== Round 4: real Chromium (Playwright), in-page fetch ===")
    finish(run())
