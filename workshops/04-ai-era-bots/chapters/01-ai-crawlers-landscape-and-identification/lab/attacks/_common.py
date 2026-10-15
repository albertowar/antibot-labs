"""Shared helpers for every attack script and for the legitimate crawlers in tools/personas_ch1.py.

Rules of engagement are absolute: these scripts run ONLY against the local demo store you run
yourself. ``tools/labclient.py`` asks the lab-root ``labnet.py`` guard for the store URL, and
that guard refuses a target that is not this machine before a single request is sent. Lab
traffic never touches a third party, a public proxy, a real crawler operator's endpoint, or
anyone else's infrastructure.

Source addresses are rented from ``data/world.json`` (RFC 5737 documentation ranges) and sent
in ``X-Lab-Client-IP``, which the store's edge honours only from loopback and only inside a
pool: an attacker may rent a different address, never invent one. Operator crawlers are tenants
of the same cloud pools as everyone else; what tells them apart is what they can prove
(data/published_ranges/, data/rdns.json), not which pool they sit in.

The point of the lab is to train defenders against your own app, not to build a scraper.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from urllib import robotparser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402  (runs the labnet guard on import)

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
    "curl": "curl/8.11.1",
    "freshrss": "FreshRSS/1.26.1 (Linux; https://freshrss.org)",
    "slack": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "uptime": "UptimeRobot/2.0; http://www.uptimerobot.com/",
}
HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

_LINK = re.compile(r'href="(/product/p\d{3})"')
_ASSET = re.compile(r'(?:href|src)="(/(?:static|img)/[^"]+)"')
_LOC = re.compile(r"<loc>[^<]*(/product/p\d{3})</loc>")


def pool_ip(pool: str, index: int) -> str:
    """The index-th address of a world.json pool: the address this actor 'rents'."""
    return world_pool(pool)[index]


class Crawler:
    """One crawler identity: a rented address, a User-Agent, and (optionally) a cookie jar.

    A crawler that does not keep cookies is a different 'visitor' on every request; one that
    does carries the store's ``sid`` cookie, which is what Round 3's cluster signal cannot see.
    """

    def __init__(self, actor: str, ip: str, ua: str, cookies: bool = False):
        self.client = LabClient(actor, ip=ip)
        self.ua, self.cookies = ua, cookies

    def get(self, path: str, accept: str = HTML, ip: str | None = None):
        if not self.cookies:
            self.client.http.cookies.clear()
        return self.client.get(path, headers=[("User-Agent", self.ua), ("Accept", accept)], ip=ip)

    def robots(self) -> robotparser.RobotFileParser:
        rp = robotparser.RobotFileParser()
        rp.parse(self.get("/robots.txt").text.splitlines())
        return rp

    def sitemap_paths(self) -> list[str]:
        return _LOC.findall(self.get("/sitemap.xml", accept="application/xml").text)

    def fetch_assets(self, html: str, limit: int | None = None) -> int:
        n = 0
        for a in asset_links(html)[:limit]:
            self.get(a, accept="*/*")
            n += 1
        return n


def product_links(html: str) -> list[str]:
    return list(dict.fromkeys(_LINK.findall(html)))


def asset_links(html: str) -> list[str]:
    return list(dict.fromkeys(_ASSET.findall(html)))


class Tally:
    """Counts what a crawl achieved: product pages served vs refused."""

    def __init__(self, catalog_size: int):
        self.catalog = catalog_size
        self.got: set[str] = set()
        self.refused: dict[int, int] = {}
        self.requests = 0
        self.t0 = time.time()

    def add(self, path: str, status: int):
        self.requests += 1
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
        return {"name": name, "attempted": self.catalog, "succeeded": len(self.got),
                "coverage": round(self.coverage, 1), "refused": self.refused, "seconds": round(secs, 1),
                "requests": self.requests}


def finish(result: dict) -> dict:
    """Print the one JSON line tools/checkpoint.py reads, and return it."""
    print(json.dumps(result))
    return result
