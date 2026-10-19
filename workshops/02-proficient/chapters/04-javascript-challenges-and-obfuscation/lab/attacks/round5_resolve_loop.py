"""
Chapter 4 — Round 5 Attack: go back to the browser whenever the budget runs out (Section 4.7)

Objective: Round 5 caps each clearance at 30 requests. The harvester from
Round 4 now gets ~30 records and then a fresh challenge. The fix is obvious:
keep the browser open and re-solve every time the budget is spent.

It works: 125/125 records. But look at the bill. Every 30 records now cost a
browser round trip, so the attacker's cost grows with volume. That's the
whole point of a JS challenge: it can't tell a patient browser from a
human, but it can make each page more expensive for a bot.

Report: records, browser solves, time spent solving, and the extrapolated
browser-seconds per 1,000 records (vs. ~0 for Round 4 at level 4).

Expected results:
  - level 5 → 125/125 records, ~5 solves

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round5_resolve_loop.py
"""

import time

from playwright.sync_api import sync_playwright

from _common import BASE_URL, PLANNED, bot_ip, browser_context, finish, report, result, scrape
from round4_playwright_harvest import harvest, to_session

ACTOR = "round5_resolve_loop"


def run():
    t_start = time.perf_counter()
    done, solves, solve_seconds, reason, state = 0, 0, 0.0, None, None
    ip = bot_ip()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser_context(browser, f"bot:{ACTOR}", ip=ip).new_page()
        while done < PLANNED:
            t0 = time.perf_counter()
            cookies, ua = harvest(page)       # re-runs the challenge when the budget is spent
            solve_seconds += time.perf_counter() - t0
            solves += 1
            got, reason, _, state = scrape(to_session(cookies, ua, ip, ACTOR), state)
            done += got
            if got == 0:                      # a fresh clearance that buys nothing: give up
                break
        browser.close()
    r = result(ACTOR, done, None if done == PLANNED else reason, time.perf_counter() - t_start, solves, solve_seconds)
    r["browser_s_per_1k"] = round(solve_seconds / max(done, 1) * 1000, 1)
    return r


if __name__ == '__main__':
    print(f"Round 5 attack: re-solve in the browser whenever the budget runs out -> {BASE_URL}")
    r = run()
    report(r)
    print(f"     attacker cost: {r['browser_s_per_1k']:.1f} browser-seconds per 1,000 records")
    finish(r)
