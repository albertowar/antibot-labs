"""The legitimate side of every round: people and welcome bots.

Fourteen personas, all synthetic, drive the store the way real traffic does:

  humans (5)          browsers that load assets, keep the session cookie and pause
                      between pages. Two of them egress from cloud addresses (iCloud
                      Private Relay, a corporate secure web gateway): the people a
                      "datacenter = bot" rule hurts first.
  non-browser (4)     an RSS reader, a Slack link unfurler, an uptime monitor and a
                      developer with curl. Automated, legitimate, and never crawling.
  declared crawlers   Googlebot and OAI-SearchBot (search), GPTBot and ClaudeBot
  (5)                 (training), all from their operators' published ranges and all
                      honouring robots.txt; plus LocalSearchBot, a small search engine
                      that publishes no ranges and no rDNS suffix. It behaves exactly
                      like Googlebot and can never prove it.

Every persona stamps X-Lab-Actor so the scoreboard can tell a blocked person from a
blocked crawler. Outcomes are read from the HTTP responses, so ungated endpoints
(feed, health) count as served.
"""

from __future__ import annotations

import os
import random
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
from _common import POOLS, UA, fetch_assets, headers, product_links, robots_parser, sitemap_paths  # noqa: E402

HUMANS = [
    {"name": "chrome-desktop",       "ip": POOLS["home-isp"][10],     "ua": UA["chrome-win"],    "pages": 6},
    {"name": "firefox-desktop",      "ip": POOLS["home-isp"][11],     "ua": UA["firefox-linux"], "pages": 5},
    {"name": "safari-ios",           "ip": POOLS["mobile-cgnat"][5],  "ua": UA["safari-ios"],    "pages": 4},
    {"name": "safari-private-relay", "ip": POOLS["relay-egress"][3],  "ua": UA["safari-mac"],    "pages": 5},
    {"name": "corporate-zscaler",    "ip": POOLS["relay-egress"][9],  "ua": UA["chrome-win"],    "pages": 6},
]
NON_BROWSER = [
    {"name": "rss-reader",     "ip": POOLS["hosting-b"][4],  "ua": UA["freshrss"], "paths": ["/feed.xml"] * 3},
    {"name": "slack-unfurl",   "ip": POOLS["cloud-a"][50],   "ua": UA["slack"],    "paths": ["/products/p042"]},
    {"name": "uptime-monitor", "ip": POOLS["hosting-b"][12], "ua": UA["uptime"],   "paths": ["/health"] * 5},
    {"name": "curl-dev",       "ip": POOLS["home-isp"][77],  "ua": UA["curl"],     "paths": ["/", "/products/p007", "/products/p008"]},
]
CRAWLERS = [
    {"name": "verified-googlebot",     "token": "Googlebot",      "ip": POOLS["google"][2]},
    {"name": "verified-oai-searchbot", "token": "OAI-SearchBot",  "ip": POOLS["openai-searchbot"][2]},
    {"name": "verified-gptbot",        "token": "GPTBot",         "ip": POOLS["openai-gptbot"][3]},
    {"name": "verified-claudebot",     "token": "ClaudeBot",      "ip": POOLS["anthropic"][2]},
    {"name": "localsearchbot",         "token": "LocalSearchBot", "ip": POOLS["localsearch"][1]},
]
CRAWL_PAGES = 12


def _outcome(resp) -> str:
    if resp.status_code == 200:
        return "allow"
    if resp.status_code == 429:
        return "limit"
    try:
        return resp.json().get("outcome", "block") if resp.status_code == 403 else "block"
    except ValueError:
        return "block"


def run_human(p: dict, base: str, rng: random.Random) -> dict:
    s = requests.Session()
    hdrs = headers(f"human:{p['name']}", p["ip"], p["ua"], {"Accept-Language": "en-GB,en;q=0.8"})
    out = []

    def pause():
        time.sleep(rng.lognormvariate(-1.3, 0.8))     # median ~0.27 s, long tail

    r = s.get(f"{base}/products?page={rng.randint(1, 6)}", headers=hdrs, timeout=5)
    out.append(_outcome(r))
    if r.status_code == 200:
        fetch_assets(s, base, r.text, hdrs)
        links = product_links(r.text)
    else:
        links = []
    pause()
    for path in rng.sample(links, min(p["pages"], len(links))):
        r = s.get(f"{base}{path}", headers=hdrs, timeout=5)
        out.append(_outcome(r))
        if r.status_code == 200:
            fetch_assets(s, base, r.text, hdrs)
        pause()
    return {"name": p["name"], "group": "humans", "outcomes": out}


def run_non_browser(p: dict, base: str) -> dict:
    hdrs = headers(f"legit:{p['name']}", p["ip"], p["ua"])
    out = []
    for path in p["paths"]:
        out.append(_outcome(requests.get(f"{base}{path}", headers=hdrs, timeout=5)))
        time.sleep(0.15)
    return {"name": p["name"], "group": "non-browser", "outcomes": out}


def run_crawler(p: dict, base: str) -> dict:
    """A polite crawler: robots.txt first, then the sitemap, only what is allowed."""
    hdrs = headers(f"legit:{p['name']}", p["ip"], UA[p["token"]])
    rp = robots_parser(base, hdrs)
    out, skipped = [], 0
    paths = sitemap_paths(requests.get(f"{base}/sitemap.xml", headers=hdrs, timeout=5).text)
    for path in paths[:CRAWL_PAGES]:
        if not rp.can_fetch(p["token"], path):
            skipped += 1
            continue
        out.append(_outcome(requests.get(f"{base}{path}", headers=hdrs, timeout=5)))
        time.sleep(0.03)
    return {"name": p["name"], "group": "crawlers", "outcomes": out, "skipped": skipped, "token": p["token"]}
