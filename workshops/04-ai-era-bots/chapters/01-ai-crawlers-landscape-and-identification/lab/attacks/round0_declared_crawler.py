"""Round 0: a declared, well-behaved training crawler (the baseline, not yet an attack).

This is what GPTBot or ClaudeBot does when it visits: it identifies itself, fetches
robots.txt, obeys it, reads the sitemap and takes every product page it is allowed to. It
comes from an address the operator publishes, so it will verify.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import UA, Crawler, Tally, finish, pool_ip  # noqa: E402

# Inside each operator's published snapshot (tools/fixtures/ranges/): the operator's own address.
ADDR = {"GPTBot": ("cloud_vm", 6), "ClaudeBot": ("cloud_vm", 27), "CCBot": ("cloud_vm", 44)}


def run(token: str = "GPTBot", ignore_robots: bool = False, delay: float = 0.03) -> dict:
    name = "gptbot-ignores-robots" if ignore_robots else "declared-crawler"
    bot = Crawler(f"bot:{name}", pool_ip(*ADDR[token]), UA[token])
    paths = bot.sitemap_paths()
    tally = Tally(len(paths))
    rp = bot.robots()
    if not ignore_robots and not rp.can_fetch(token, "/sitemap.xml"):
        print(f"[{token}] robots.txt forbids even the sitemap; leaving.")
        return tally.report(f"round0 {token}")
    skipped = 0
    for path in paths:
        if not ignore_robots and not rp.can_fetch(token, path):
            skipped += 1
            continue
        tally.add(path, bot.get(path).status_code)
        time.sleep(delay)
    if skipped:
        print(f"[{token}] robots.txt disallowed {skipped} product URLs; the crawler did not request them.")
    return tally.report(f"round0 {token}{' (ignoring robots.txt)' if ignore_robots else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", default="GPTBot", choices=sorted(ADDR))
    ap.add_argument("--ignore-robots", action="store_true")
    a = ap.parse_args()
    finish(run(a.token, a.ignore_robots))
