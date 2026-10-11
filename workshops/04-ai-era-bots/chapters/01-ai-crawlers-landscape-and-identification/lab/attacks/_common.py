"""Shared helpers and the ethics guardrail for every attack script and tool.

Rules of engagement are absolute: these scripts run ONLY against the local demo
store you run yourself. ``require_local`` enforces it in code: a non-loopback target
raises before a single request is sent. Lab traffic never touches a third party, a
public proxy, a real crawler operator's endpoint, or anyone else's infrastructure.

The source addresses come from data/world.json (RFC 5737 documentation ranges). The
store honours ``X-Lab-Source-IP`` only from loopback, as a stand-in for the egress a
real crawler would rent. The point of the lab is to train defenders against your own
app, not to build a scraper.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from urllib import robotparser
from urllib.parse import urlparse

import requests

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(LAB_DIR, "data")

with open(os.path.join(DATA, "world.json")) as _fh:
    WORLD = json.load(_fh)
POOLS = {name: pool["ips"] for name, pool in WORLD["pools"].items()}

# The strings the operators document (Oct 2026). Versions change; the token does not.
UA = {
    "GPTBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot",
    "OAI-SearchBot": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot"),
    "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    "ClaudeBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "Claude-SearchBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)",
    "CCBot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "Googlebot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/141.0.0.0 Safari/537.36",
    "PerplexityBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
    "LocalSearchBot": "Mozilla/5.0 (compatible; LocalSearchBot/1.0; +https://localsearch.example/bot)",
    # The exact string Cloudflare reported for Perplexity's undeclared crawler (Aug 2025).
    "stealth-chrome": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "chrome-win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "firefox-linux": "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
    "safari-ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "safari-mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "curl": "curl/8.11.1",
    "freshrss": "FreshRSS/1.26.1 (Linux; https://freshrss.org)",
    "slack": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "uptime": "UptimeRobot/2.0; http://www.uptimerobot.com/",
}

_LINK = re.compile(r'href="(/products/p\d{3})"')
_ASSET = re.compile(r'(?:href|src)="(/static/[^"]+)"')
_LOC = re.compile(r"<loc>[^<]*(/products/p\d{3})</loc>")


def require_local(url: str) -> str:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url
    except ValueError:
        pass
    raise SystemExit(
        f"Refusing to run against non-local target {host!r}. This lab only ever targets the "
        f"local demo store (127.0.0.1). Do not remove this check to 'try it on something real'.")


def headers(actor: str, ip: str, ua: str, extra: dict | None = None) -> dict:
    h = {"X-Lab-Actor": actor, "X-Lab-Source-IP": ip, "User-Agent": ua,
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if extra:
        h.update(extra)
    return h


def product_links(html: str) -> list[str]:
    return list(dict.fromkeys(_LINK.findall(html)))


def asset_links(html: str) -> list[str]:
    return list(dict.fromkeys(_ASSET.findall(html)))


def sitemap_paths(xml: str) -> list[str]:
    return _LOC.findall(xml)


def robots_parser(base: str, hdrs: dict) -> robotparser.RobotFileParser:
    rp = robotparser.RobotFileParser()
    r = requests.get(f"{base}/robots.txt", headers=hdrs, timeout=5)
    rp.parse(r.text.splitlines())
    return rp


def fetch_assets(session, base: str, html: str, hdrs: dict) -> int:
    n = 0
    for a in asset_links(html):
        session.get(f"{base}{a}", headers=hdrs, timeout=5)
        n += 1
    return n


class Tally:
    """Counts what a crawl achieved: product pages served vs refused."""

    def __init__(self, catalog_size: int):
        self.catalog = catalog_size
        self.got: set[str] = set()
        self.refused: dict[int, int] = {}
        self.t0 = time.time()

    def add(self, path: str, status: int):
        if status == 200:
            self.got.add(path)
        else:
            self.refused[status] = self.refused.get(status, 0) + 1

    @property
    def coverage(self) -> float:
        return 100.0 * len(self.got) / self.catalog if self.catalog else 0.0

    def report(self, name: str) -> dict:
        secs = time.time() - self.t0
        refused = ", ".join(f"{n}x{code}" for code, n in sorted(self.refused.items())) or "none"
        print(f"[{name}] coverage {len(self.got)}/{self.catalog} product pages ({self.coverage:.0f}%)  "
              f"refused: {refused}  in {secs:.1f}s")
        return {"name": name, "got": len(self.got), "catalog": self.catalog,
                "coverage": self.coverage, "refused": self.refused, "seconds": secs}


def catalog_size(base: str) -> int:
    return int(requests.get(f"{base}/admin/status", timeout=5).json()["catalog_size"])
