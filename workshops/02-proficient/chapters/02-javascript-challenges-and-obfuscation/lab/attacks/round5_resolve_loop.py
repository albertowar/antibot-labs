"""
Chapter 2 — Round 5 Attack: go back to the browser whenever the budget runs out (Section 2.7)

Objective: Round 5 caps each clearance at 30 requests. The harvester from
Round 4 now gets ~29 pages and then a fresh challenge. The fix is obvious:
keep the browser open and re-solve every time the budget is spent.

It works: 300/300 pages. But look at the bill. Every 29 pages now cost a
browser round trip, so the attacker's cost grows with volume. That's the
whole point of a JS challenge: it can't tell a patient browser from a
human, but it can make each page more expensive for a bot.

Report: pages, browser solves, time spent solving, and the extrapolated
browser-seconds per 1,000 pages (vs. ~0 for Round 4 at level 4).

Expected results:
  - DEFENSE_LEVEL=5 → 300/300 pages, ~11 solves

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=5 python app.py
Then run:
    python attacks/round5_resolve_loop.py
"""

import time

from playwright.sync_api import sync_playwright

from common import BASE_URL, PAGES, report, require_local, result, scrape
from round4_playwright_harvest import harvest, to_session


def run():
    require_local()
    t_start = time.perf_counter()
    done, solves, solve_seconds, reason = 0, 0, 0.0, None
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        while done < PAGES:
            t0 = time.perf_counter()
            cookies, ua = harvest(page)       # re-runs the challenge when the budget is spent
            solve_seconds += time.perf_counter() - t0
            solves += 1
            got, reason, _ = scrape(to_session(cookies, ua), pages=PAGES - done, start=done + 1)
            done += got
            if got == 0:                      # a fresh clearance that buys nothing: give up
                break
        browser.close()
    r = result("round5_resolve_loop", done, None if done == PAGES else reason,
               time.perf_counter() - t_start, solves, solve_seconds)
    r["browser_s_per_1k"] = solve_seconds / max(done, 1) * 1000
    return r


if __name__ == '__main__':
    print(f"Round 5 attack: re-solve in the browser whenever the budget runs out -> {BASE_URL}")
    r = run()
    report(r)
    print(f"     attacker cost: {r['browser_s_per_1k']:.1f} browser-seconds per 1,000 pages")
