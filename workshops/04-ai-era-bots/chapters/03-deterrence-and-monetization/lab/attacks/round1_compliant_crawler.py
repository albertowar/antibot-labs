"""Round 1 attack (the honest half): a compliant training crawler.

LabTrainBot does everything a well-run crawler does. It announces itself in the User-Agent, crawls
from its operator's published range, reads robots.txt and obeys its own group, stops when the first
page carries an AIPREF `Content-Usage: train-ai=n` header, and reports the RSL licence it found.

Against DEFENSE_LEVEL=0, or against the Round 1 stub, it finds no policy at all and takes the
catalogue in good faith. Once you publish the policy it fetches robots.txt and leaves. The point of
running the honest crawler first: a published preference is a real control for the crawlers that
read it, and no control at all for the ones that don't (see round1_ignoring_crawler.py).

    python attacks/round1_compliant_crawler.py
"""

from __future__ import annotations

import re

from _common import BASE_URL, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, finish


def run(budget=400):
    c = Crawler("compliant", TRAINBOT_UA, TRAINBOT_RANGE, budget=budget, obey_robots=True,
                robots_token="LabTrainBot", purpose="ai-train", follow_hidden=False, label="compliant LabTrainBot")
    rep = c.crawl()
    robots = c.robots_text
    group = re.search(r"User-agent: LabTrainBot\n((?:(?!User-agent).*\n)*)", robots)
    lic = re.search(r"^License: (.*)$", robots, re.M)
    cu = re.search(r"^Content-Usage: (.*)$", robots, re.M)
    print("robots.txt group for LabTrainBot:", group.group(1).strip().replace("\n", " | ") if group else "(none)")
    print("License line:", lic.group(1) if lic else "(none)")
    print("Content-Usage (robots.txt line):", cu.group(1) if cu else "(none)")
    if lic:
        r = c._get(lic.group(1).replace(BASE_URL, ""))
        print("RSL prohibits:", re.findall(r"<prohibits[^>]*>([^<]*)</prohibits>", r.text) or "(nothing)")
    return finish(rep)


if __name__ == "__main__":
    rep = run()
    print("\nThe compliant crawler got", f"{rep['coverage']:.0%}", "of the catalogue.",
          "Publish the policy and it should get 0%." if rep["coverage"] > 0 else "The policy worked on it.")
