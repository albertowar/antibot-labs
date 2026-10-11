"""Legitimate-traffic simulator — the other half of every round's scoreboard.

Four cohorts of people and services the store must keep serving, whatever it
does to crawlers. Each stamps ``X-Lab-Actor`` so the scoreboard can tell a
blocked crawler from a blocked customer:

  human     40 shoppers in current browsers, one residential IP each: home,
            a catalogue page, 3-6 products. Must never be blocked, charged,
            or shown a decoy page.
  prefetch   5 shoppers whose browser prefetches the links on the page they
            are reading (Speculation Rules, "instant page" plugins). They
            follow every *visible* link, never hidden or nofollow ones. The
            maze's false positive if its entry link is not hidden properly.
  reader     3 text-mode / accessibility users (Lynx, w3m). Their User-Agent
            is neither a browser nor a declared crawler. The false positive of
            any rule that treats "unfamiliar UA" as "bot".
  search     1 verified search crawler (LabSearchBot, signed, from its
            published range) that obeys robots.txt and indexes 30 pages. Its
            policy is search=yes: blocking or charging it costs you referrals.

All users, IPs and keys are synthetic.

    python tools/legit_traffic.py            # run all cohorts, summarise
    python tools/legit_traffic.py --cohort human
"""

from __future__ import annotations

import argparse
import collections
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
from _common import (BASE_URL, CHROME_UA, RESIDENTIAL, SEARCHBOT_RANGE, SEARCHBOT_UA,  # noqa: E402
                     Crawler, extract_links, require_local, searchbot_signer)

OUTCOME = {200: "allow", 403: "block", 402: "paywall"}
READER_UAS = ["Lynx/2.9.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/3.0.13",
              "w3m/0.5.3+git20230121", "ELinks/0.17.1 (textmode; Linux; 80x24-2)"]


def _outcome(r):
    if r.status_code == 200 and "noindex" in r.text[:600] and "/maze/" in r.text:
        return "maze"          # a decoy page served where content was expected
    return OUTCOME.get(r.status_code, str(r.status_code))


def _session(ua, ip, actor):
    c = httpx.Client(timeout=10, headers={"User-Agent": ua, "X-Lab-Client-IP": ip, "X-Lab-Actor": actor})
    return c


def _shop(c, base, rng, prefetch=False):
    out = []
    r = c.get(f"{base}/")
    out.append(_outcome(r))
    page = rng.randint(1, 15)
    r = c.get(f"{base}/catalog?page={page}")
    out.append(_outcome(r))
    links = [h for h, hidden in extract_links(r.text) if h.startswith("/product/") and not hidden]
    if prefetch:
        # Speculation Rules / prefetch plugin: every visible same-origin product link.
        for h in links:
            out.append(_outcome(c.get(f"{base}{h}")))
        hidden = [h for h, hid in extract_links(r.text) if hid]
        out.extend("skipped-hidden" for _ in hidden)
    else:
        for h in rng.sample(links, min(len(links), rng.randint(3, 6))):
            out.append(_outcome(c.get(f"{base}{h}")))
    return out


def cohort_human(base, n=40):
    def one(i):
        rng = random.Random(100 + i)
        with _session(CHROME_UA, RESIDENTIAL[200 + i], "human") as c:
            return _shop(c, base, rng)
    with ThreadPoolExecutor(max_workers=8) as ex:
        return [o for outs in ex.map(one, range(n)) for o in outs]


def cohort_prefetch(base, n=5):
    out = []
    for i in range(n):
        rng = random.Random(500 + i)
        with _session(CHROME_UA, RESIDENTIAL[180 + i], "prefetch") as c:
            out.extend(_shop(c, base, rng, prefetch=True))
    return out


def cohort_reader(base, n=3):
    out = []
    for i in range(n):
        rng = random.Random(700 + i)
        with _session(READER_UAS[i % len(READER_UAS)], RESIDENTIAL[170 + i], "reader") as c:
            out.extend(_shop(c, base, rng))
    return out


def cohort_search(base, budget=30):
    c = Crawler(base, SEARCHBOT_UA, SEARCHBOT_RANGE, actor="search", budget=budget, obey_robots=True, robots_token="LabSearchBot", purpose="search",
                follow_hidden=False, signer=searchbot_signer(), label="verified LabSearchBot")
    c.crawl()
    out = []
    for code, n in c.stats.items():
        if code.isdigit():
            out.extend([OUTCOME.get(int(code), code)] * n)
    out.extend(["maze"] * c.stats["maze_pages"])
    return out


COHORTS = {"human": cohort_human, "prefetch": cohort_prefetch, "reader": cohort_reader,
           "search": cohort_search}


def run_legit(base=BASE_URL, cohorts=None):
    """Run the cohorts; return {cohort: Counter(outcomes)}."""
    require_local(base)
    return {name: collections.Counter(COHORTS[name](base)) for name in (cohorts or COHORTS)}


def hurt(tallies) -> int:
    """How many legitimate requests were blocked, charged, paywalled or mazed."""
    return sum(v for t in tallies.values() for k, v in t.items()
               if k in ("block", "paywall", "charged", "maze"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cohort", choices=list(COHORTS), default=None)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    res = run_legit(a.url, [a.cohort] if a.cohort else None)
    for name, t in res.items():
        print(f"{name:9s} {dict(t)}")
    print(f"legitimate requests hurt (block/402/charged/maze): {hurt(res)}")
