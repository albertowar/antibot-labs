"""Round 1 attack (the honest half): a compliant training crawler.

LabTrainBot does everything a well-run crawler does. It announces itself in the
User-Agent, crawls from its operator's published range, reads robots.txt and
obeys its own group, stops when the first page carries an AIPREF
`Content-Usage: train-ai=n` header, and reports the RSL licence it found.

Against DEFENSE_LEVEL=0, or against the Round 1 stub, it finds no policy at
all and takes the catalogue in good faith. Once you publish the policy it
fetches robots.txt and leaves. The point of running the honest crawler first:
a published preference is a real control for the crawlers that read it, and
no control at all for the ones that don't (see round1_ignoring_crawler.py).

    python attacks/round1_compliant_crawler.py
"""

from __future__ import annotations

import re
import sys

from _common import BASE_URL, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, print_report, require_local


def run(base=BASE_URL, budget=400):
    require_local(base)
    c = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, budget=budget, obey_robots=True, robots_token="LabTrainBot", purpose="ai-train",
                follow_hidden=False, label="compliant LabTrainBot")
    rep = c.crawl()
    robots = getattr(c, "robots_text", "")
    group = re.search(r"User-agent: LabTrainBot\n((?:(?!User-agent).*\n)*)", robots)
    lic = re.search(r"^License: (.*)$", robots, re.M)
    print("robots.txt group for LabTrainBot:", group.group(1).strip().replace("\n", " | ") if group else "(none)")
    print("License line:", lic.group(1) if lic else "(none)")
    cu = re.search(r"^Content-Usage: (.*)$", robots, re.M)
    print("Content-Usage (robots.txt line):", cu.group(1) if cu else "(none)")
    if lic:
        r = c.client.get(lic.group(1), headers={"User-Agent": TRAINBOT_UA, "X-Lab-Actor": "bot"})
        prohibits = re.findall(r"<prohibits[^>]*>([^<]*)</prohibits>", r.text)
        print("RSL prohibits:", prohibits or "(nothing)")
    print_report(rep)
    return rep


if __name__ == "__main__":
    rep = run(sys.argv[1] if len(sys.argv) > 1 else BASE_URL)
    print("\nThe compliant crawler got", f"{rep['coverage']:.0%}", "of the catalogue.",
          "Publish the policy and it should get 0%." if rep["coverage"] > 0 else "The policy worked on it.")
