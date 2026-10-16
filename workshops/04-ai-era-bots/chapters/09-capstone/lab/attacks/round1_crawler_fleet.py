"""
Round 1 attack — the crawler fleet (🔴 against crawl governance).

Four crawlers hit the same catalogue, each the archetype W4 Ch1–Ch3 named:

    training crawler   declared LabTrainBot, ignores robots.txt, unsigned and
                       from its *published* range so it verifies on IP. Wants
                       the catalogue for free.
    impostor           claims LabSearchBot from a datacenter address outside the
                       published range, unsigned (the "fake Googlebot" of W4 Ch2).
    stealth crawler    a stock-Chrome UA from a datacenter, declares nothing,
                       follows every link including the hidden one.
    paying crawler     declared LabTrainBot, SIGNED (Web Bot Auth), reads the RSL
                       licence and pays the per-page price (the one that is meant
                       to get through — monetization, not a block).

A free-path leak probe then asks the JSON API, the sitemap and search directly:
every carrier of catalogue data must sit behind the same policy, or the paywall
leaks (W4 Ch3).

    python attacks/round1_crawler_fleet.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import (CHROME_UA, Crawler, DATACENTER, SEARCHBOT_RANGE, TRAINBOT_RANGE, TRAINBOT_UA,  # noqa: E402
                     print_report, target, trainbot_signer)

IMPOSTOR_UA = "Mozilla/5.0 (compatible; LabSearchBot/2.1; +https://labsearch.example/bot)"


def run(base=None, budget=60):
    base = target() if base is None else base
    print("Round 1 — the crawler fleet:\n")
    results = {}

    results["training"] = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, actor="bot:r1_training", budget=budget,
                                  obey_robots=False, robots_token="LabTrainBot", purpose="ai-train",
                                  label="training crawler (ignores robots, unsigned)").crawl()
    print_report(results["training"])

    results["impostor"] = Crawler(base, IMPOSTOR_UA, DATACENTER, actor="bot:r1_impostor", budget=budget,
                                  obey_robots=False, robots_token="LabSearchBot", purpose="search",
                                  label="impostor LabSearchBot (datacenter, unsigned)").crawl()
    print_report(results["impostor"])

    # One cheap cloud box, not a rotating pool: it follows the hidden entry link and the
    # maze tags its IP. A rotating pool dilutes the tag (that is Round 4's escalation).
    results["stealth"] = Crawler(base, CHROME_UA, [DATACENTER[0]], actor="bot:r1_stealth", budget=budget,
                                 obey_robots=False, follow_hidden=True, browser_headers=True,
                                 label="stealth crawler (Chrome UA, one datacenter IP)").crawl()
    print_report(results["stealth"])
    # Second pass from the same IP: now tagged, the catalogue is dark.
    results["stealth_pass2"] = Crawler(base, CHROME_UA, [DATACENTER[0]], actor="bot:r1_stealth2", budget=budget,
                                       obey_robots=False, follow_hidden=True, browser_headers=True,
                                       label="stealth crawler, second pass (IP now maze-tagged)").crawl()
    print_report(results["stealth_pass2"])

    results["paying"] = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, actor="bot:r1_paying", budget=budget,
                                obey_robots=True, robots_token="LabTrainBot", purpose="ai-train", licensed=True,
                                follow_hidden=False, signer=trainbot_signer(), pay={"mode": "reactive", "max": 0.05},
                                label="paying LabTrainBot (signed, pays the RSL price)").crawl()
    print_report(results["paying"])

    # Leak probe: an unpaid but verified training crawler must meet the paywall on EVERY
    # carrier of catalogue data, not just the HTML pages (W4 Ch3's lesson).
    import httpx
    leaks = 0
    sig = trainbot_signer()
    with httpx.Client(timeout=10) as c:
        for path in ("/api/products?page=1", "/sitemap.xml", "/search?q=runner"):
            h = {"User-Agent": TRAINBOT_UA, "X-Lab-Client-IP": TRAINBOT_RANGE[0], "X-Lab-Actor": "bot:r1_leak"}
            h.update(sig.headers(base.split("//", 1)[-1]))
            r = c.get(f"{base}{path}", headers=h)
            if r.status_code == 200 and re.search(r"p0\d\d", r.text):
                leaks += 1
    print(f"  [free-path leak probe] {leaks}/3 content carriers served free to the unpaid training crawler "
          f"(every carrier should be 402)")
    results["free_path_leaks"] = leaks
    return results


if __name__ == "__main__":
    run()
