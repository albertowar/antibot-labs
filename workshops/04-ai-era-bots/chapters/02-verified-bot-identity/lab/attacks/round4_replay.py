"""Round 4 attack (b): replay a signed request that leaked.

A Web Bot Auth signature covering only `@authority` and `signature-agent` is
valid for any method, path or body sent to that host until it expires. Signed
requests leak all the time: CDN and proxy logs, debugging pastes, a browser
extension's traffic dump. Two leaks from the mock's "paste site":

  stale: a ChatGPT-User request signed an hour ago with a 24-hour window
  fresh: one signed seconds ago with a 60-second window, replayed 200 times

The signatures are genuine (the real chatgpt.com key signed them). Verification
passes. Only policy can refuse them: a window cap for the stale one, a nonce
replay cache for the fresh one.

Expected: L4 -> 200/200 and 200/200. L5 -> 0/200 (window) and 1/200 (nonce).

    python attacks/round4_replay.py
"""

from __future__ import annotations

import httpx

from _common import ATTACKER_IP, BASE_URL, MOCK_URL, headers, report, require_local_target, scrape_catalog


def replay(c: httpx.Client, leak: dict, actor: str) -> dict:
    hdrs = headers(actor, ATTACKER_IP, leak["headers"]["User-Agent"],
                   {k: v for k, v in leak["headers"].items() if k != "User-Agent"})
    return scrape_catalog(c, hdrs)


def run(base: str = BASE_URL, mock_url: str = MOCK_URL) -> dict:
    require_local_target(base)
    require_local_target(mock_url)
    authority = base.split("://", 1)[1].rstrip("/")
    with httpx.Client(base_url=mock_url, timeout=10) as mock, httpx.Client(base_url=base, timeout=10) as c:
        c.post("/admin/reset", params={"scope": "budgets"})   # a fresh minute, same caches
        stale = replay(c, mock.get("/leak/stale", params={"authority": authority}).json(), "bot-replay-stale")
        c.post("/admin/reset", params={"scope": "budgets"})
        fresh = replay(c, mock.get("/leak/fresh", params={"authority": authority}).json(), "bot-replay-fresh")
    return {"stale": stale, "fresh": fresh, "scraped": stale["scraped"] + fresh["scraped"], "total": 2 * stale["total"]}


if __name__ == "__main__":
    print("=== Round 4b: replay leaked ChatGPT-User signatures ===")
    out = run()
    report("stale leak, 24 h window ", out["stale"])
    report("fresh leak, 60 s window ", out["fresh"])
