"""Round 0: a declared, well-behaved training crawler (the baseline, not yet an attack).

This is what GPTBot or ClaudeBot does when it visits: it identifies itself, fetches
robots.txt, obeys it, reads the sitemap and takes every product page it is allowed
to. It comes from the operator's published address range, so it will verify.

At Round 0 our robots.txt allows everything, so a training crawler takes 100% of the
catalog, politely. That is the default state of most of the web and the reason this
chapter exists: nobody asked, and nothing stopped it. Round 1 writes the policy.

    python attacks/round0_declared_crawler.py                 # GPTBot, honours robots.txt
    python attacks/round0_declared_crawler.py --token ClaudeBot
    python attacks/round0_declared_crawler.py --ignore-robots # what a dishonest token does
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, POOLS, UA, Tally, catalog_size, headers, require_local, robots_parser, sitemap_paths  # noqa: E402

POOL_OF = {"GPTBot": "openai-gptbot", "ClaudeBot": "anthropic", "CCBot": "commoncrawl"}


def run(base: str = BASE_URL, token: str = "GPTBot", ignore_robots: bool = False, delay: float = 0.03) -> dict:
    require_local(base)
    ip = POOLS[POOL_OF[token]][1]
    hdrs = headers("attack:round0", ip, UA[token])
    tally = Tally(catalog_size(base))
    rp = robots_parser(base, hdrs)
    if not ignore_robots and not rp.can_fetch(token, "/sitemap.xml"):
        print(f"[{token}] robots.txt forbids even the sitemap; leaving.")
        return tally.report(f"round0 {token}")
    r = requests.get(f"{base}/sitemap.xml", headers=hdrs, timeout=5)
    skipped = 0
    for path in sitemap_paths(r.text):
        if not ignore_robots and not rp.can_fetch(token, path):
            skipped += 1
            continue
        resp = requests.get(f"{base}{path}", headers=hdrs, timeout=5)
        tally.add(path, resp.status_code)
        time.sleep(delay)
    if skipped:
        print(f"[{token}] robots.txt disallowed {skipped} product URLs; the crawler did not request them.")
    return tally.report(f"round0 {token}{' (ignoring robots.txt)' if ignore_robots else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--token", default="GPTBot", choices=sorted(POOL_OF))
    ap.add_argument("--ignore-robots", action="store_true")
    a = ap.parse_args()
    run(a.url, a.token, a.ignore_robots)
