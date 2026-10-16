"""
Round 0 attack — the naive fleet, no tricks.

Three cheap clients that the end-of-W4 stack stops without anyone touching a
defense, run once at L0 (run the store with LAB_SHADOW=1 to watch every layer above the level report in X-Lab-Shadow) to set the baseline and prove
the store works end to end:

    training crawler   a declared LabTrainBot that ignores robots.txt and
                       harvests the catalogue
    undeclared agent   an agent in a stock Chrome that logs into an aged
                       account and buys the drop
    text extractor     reads one catalogue page as text and asks the model for JSON

At L0 all three succeed: that is the point of Round 0. Run the rounds to watch
each one get governed.

    python attacks/round0_naive.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import (CHROME_UA, Cost, Crawler, RESIDENTIAL, TRAINBOT_RANGE, TRAINBOT_UA,  # noqa: E402
                     owner_accounts, print_report, report, summary, target)
from _http_agent import run_session  # noqa: E402


def run(base=None):
    base = target() if base is None else base
    print("Round 0 — baseline (store at L0; everything the rounds add runs in shadow):\n")
    with Cost() as cost:
        crawl = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, actor="bot:r0_crawler", budget=40, obey_robots=False,
                        robots_token="LabTrainBot", label="training crawler").crawl()
    print_report(crawl)
    acct = owner_accounts(1)[0]
    res = [run_session(base, acct, actor="bot:r0_agent", egress=RESIDENTIAL[9], declared="none", attended=True)]
    s = summary("undeclared agent", res, cost)
    report(s)
    from round3_llm_extract import run as extract
    ex = extract(base, pages=1, actor="bot:r0_extract", quiet=True)
    print(f"  [text extractor] harvested {ex['harvested']} records from 1 page "
          f"(honeypot pages fetched {ex['honeypot_hits']}, canaries {ex['canaries']})")
    print("\nBaseline: the crawler harvests, the agent buys, the extractor reads. "
          "Switch on the levels and watch each number fall.")
    return {"crawler": crawl, "agent": s, "extract": ex}


if __name__ == "__main__":
    run()
