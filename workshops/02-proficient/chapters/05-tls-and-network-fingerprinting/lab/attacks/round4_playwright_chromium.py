"""
Chapter 5 — Round 4 Attack: stop pretending, drive a real browser (Section 5.8)

Objective: beat the JS engine proof. A real Chromium has the real
ClientHello, the real HTTP/2 preface and a real V8, so it passes every
layer in this chapter. The only changes are a UA without "HeadlessChrome"
(W1 Ch3 would catch that) and scraping with in-page fetch().

Gotcha: Playwright's `page.request` / `context.request` API does NOT use the
browser's network stack. It sends from Node.js with Node's TLS, which has a
completely different JA4. Bots that mix the two leak that fingerprint.

The cost moves to the attacker: compare this script's requests/second with
Round 3 (tools/checkpoint.py prints it). Memory matters more at scale: one
headless Chromium worker measured ~600 MB RSS against ~40 MB for curl_cffi.
Catching it is the job of W2 Ch1 (automation artifacts) and W2 Ch3 (behavior).

Expected results:
  - DEFENSE_LEVEL=4 → 200 on every request

Run:
    python attacks/round4_playwright_chromium.py
"""

from playwright.sync_api import sync_playwright

from _lab import BASE_URL, CHROME_UA, report, to_result

PATH = "/api/products"
REQUESTS = 10

SCRAPE_JS = """async ([path, n]) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = await fetch(path);
    out.push({status: r.status, data: await r.json()});
  }
  return out;
}"""


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(user_agent=CHROME_UA, ignore_https_errors=True)
        page = context.new_page()
        page.goto(BASE_URL + "/")
        page.wait_for_function("window.__productsStatus !== undefined", timeout=10_000)
        rows = page.evaluate(SCRAPE_JS, [PATH, REQUESTS])
        browser.close()
    return [to_result(PATH, row["status"], row["data"]) for row in rows]


if __name__ == "__main__":
    print("=== Round 4: real Chromium (Playwright), in-page fetch ===")
    report(run())
