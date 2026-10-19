"""
Chapter 4 — Rounds 0-1 Attack: a plain HTTP scraper (Section 4.7)

Objective: scrape the whole catalogue with requests. No JavaScript, no browser. This is the bulk
of real-world scraping traffic, and it's what a JavaScript challenge exists to filter out.

Expected results:
  - level 0   → 125/125 records
  - level 1+  → 0/125: challenge_required (the catalogue now needs the challenge's pass)

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round1_requests_scraper.py
"""

from _common import BASE_URL, finish, lab_session, report, result, scrape


def run():
    ok, reason, seconds, _ = scrape(lab_session("round1_requests_scraper"))
    return result("round1_requests_scraper", ok, reason, seconds)


if __name__ == '__main__':
    print(f"Round 1 attack: plain requests scraper -> {BASE_URL}")
    r = run()
    report(r)
    finish(r)
