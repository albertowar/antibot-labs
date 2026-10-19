"""
W4 Ch10 Capstone — shared crawler engine and Web Bot Auth signer (from W4 Ch3)

Used by both sides: tools/legit_traffic.py drives the verified search crawler,
the licensed (paying) crawler and the prefetching browsers with it, and
attacks/round1_crawler_fleet.py drives the impostors. The ethics guardrail is
built in: a non-loopback target raises before a single request is sent
(labnet.py via tools/labclient.py).

Egress comes from the shared world (data/world.json), claimed with
X-Lab-Client-IP and honoured by the store only from loopback. The two lab
operators' *published* ranges are the cloud_vm pool (LabTrainBot, 203.0.113.0/26)
and the hosting_asn pool (LabSearchBot, 203.0.113.64/26) — the same CIDRs
defenses/crawler_registry.py lists. cloud_gcp is "a datacenter nobody
published"; the home_* pools are residential.

``Crawler`` is a deliberately simple breadth-first fetcher: a frontier, a page
budget, link extraction with the stdlib HTML parser, and hooks for the choices
each round makes (obey robots.txt or not, sign or not, pay or not, follow
hidden links or not). Just strong enough to beat the previous round.

Signing is the canonical Ch2 stack: tools/make_keys.py generates each operator's
Ed25519 key and signed key directory; ``Signer`` adds Signature-Agent and an
RFC 9421 signature over ("@authority" "signature-agent") to every request,
with a fresh nonce (defenses/web_bot_auth.py replays-checks it).
"""

import os
import re
import sys
import time
import urllib.robotparser
from collections import Counter, deque
from urllib.parse import urljoin, urlparse

import httpx
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, LAB_DIR)

import labclient  # noqa: E402  (runs the labnet guard on import)
import make_keys  # noqa: E402
from labclient import world_pool  # noqa: E402
from defenses import httpsig  # noqa: E402

BASE_URL = labclient.BASE_URL
CATALOGUE_SIZE = 120

TRAINBOT_UA = "Mozilla/5.0 (compatible; LabTrainBot/1.0; +https://trainbot.example/bot)"
SEARCHBOT_UA = "Mozilla/5.0 (compatible; LabSearchBot/2.1; +https://labsearch.example/bot)"
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/150.0.0.0 Safari/537.36")
BROWSER_HEADERS = {"Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

TRAINBOT_RANGE = world_pool("cloud_vm")       # published: 203.0.113.0/26
SEARCHBOT_RANGE = world_pool("hosting_asn")   # published: 203.0.113.64/26
DATACENTER = world_pool("cloud_gcp")          # unpublished cloud
RESIDENTIAL = (world_pool("home_broadband") + world_pool("home_cable")
               + world_pool("home_fiber") + world_pool("home_eu"))

SKU_RE = re.compile(r"/product/(p\d{3})\b")
MD_SKU = re.compile(r"\b(p\d{3})\b")


class Signer:
    """Signs requests the way a registered crawler operator would (RFC 9421, Ed25519, Web Bot Auth tag)."""

    def __init__(self, key_name, agent_origin):
        self.key, self.keyid = make_keys.load_signer(key_name)
        self.agent = agent_origin

    def headers(self, authority):
        ctx = httpsig.MessageContext("GET", authority, "/", {}, "http", "")
        return httpsig.agent_headers(self.key, self.keyid, self.agent, ctx)


def trainbot_signer():
    return Signer("trainbot.example", "https://trainbot.example")


def searchbot_signer():
    return Signer("labsearch.example", "https://labsearch.example")


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []   # (href, is_hidden_or_nofollow)

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        a = dict(attrs)
        href = a.get("href")
        if not href:
            return
        hidden = ("nofollow" in (a.get("rel") or "") or "hp" in (a.get("class") or "")
                  or a.get("aria-hidden") == "true" or a.get("tabindex") == "-1")
        self.links.append((href, hidden))


def extract_links(html_text):
    p = Links()
    p.feed(html_text)
    return p.links


def is_maze_page(resp):
    return resp.status_code == 200 and "noindex" in resp.text[:800] and "/maze/" in resp.text


class Crawler:
    def __init__(self, base, ua, ips, actor="bot", budget=200, obey_robots=False, follow_hidden=True,
                 signer=None, pay=None, label="crawler", robots_token=None, purpose="ai-train",
                 browser_headers=False, delay=0.0, licensed=False):
        self.base = labclient.assert_local(base).rstrip("/")
        self.ua, self.ips, self.actor = ua, list(ips), actor
        self.robots_token = robots_token or ua.split("/")[0]
        self.purpose = purpose
        self.budget, self.obey_robots, self.follow_hidden = budget, obey_robots, follow_hidden
        self.signer, self.pay, self.label = signer, pay, label
        self.browser_headers, self.delay = browser_headers, delay
        self.licensed = licensed
        self.authority = urlparse(self.base).netloc
        self.rp = None
        self.seen, self.skus, self.stats = set(), set(), Counter()
        self.spent, self._ip_i = 0.0, 0
        self.client = httpx.Client(timeout=15)

    def _ip(self):
        ip = self.ips[self._ip_i % len(self.ips)]
        self._ip_i += 1
        return ip

    def _headers(self, extra=None):
        h = {"User-Agent": self.ua, "X-Lab-Client-IP": self._ip(), "X-Lab-Actor": self.actor,
             "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
        if self.browser_headers:
            h.update(BROWSER_HEADERS)
        if self.signer:
            h.update(self.signer.headers(self.authority))
        if extra:
            h.update(extra)
        return h

    def read_robots(self):
        r = self.client.get(f"{self.base}/robots.txt", headers=self._headers())
        self.stats["requests"] += 1
        self.rp = urllib.robotparser.RobotFileParser()
        self.rp.parse(r.text.splitlines())
        self.robots_text = r.text
        return r.text

    def allowed(self, url):
        if self.obey_robots and self.rp and not self.rp.can_fetch(self.robots_token, url):
            return False
        return True

    def fetch(self, url):
        extra = {}
        if self.pay and self.pay.get("mode") == "proactive":
            extra["crawler-max-price"] = f"USD {self.pay['max']:.2f}"
        try:
            r = self.client.get(url, headers=self._headers(extra))
        except httpx.HTTPError as exc:
            self.stats["requests"] += 1
            self.stats["errors"] += 1
            return httpx.Response(599, request=httpx.Request("GET", url), text=str(exc))
        self.stats["requests"] += 1
        if r.status_code == 402:
            price = r.headers.get("crawler-price", "")
            if self.pay and self.pay.get("mode") == "reactive":
                amount = float(price.split()[-1]) if price else None
                if amount is not None and amount <= self.pay["max"]:
                    r = self.client.get(url, headers=self._headers({"crawler-exact-price": f"USD {amount:.2f}"}))
                    self.stats["requests"] += 1
        if r.headers.get("crawler-charged"):
            self.spent += float(r.headers["crawler-charged"].split()[-1])
            self.stats["charged"] += 1
        self.stats[str(r.status_code)] += 1
        if is_maze_page(r):
            self.stats["maze_pages"] += 1
        if self.delay:
            time.sleep(self.delay)
        return r

    def crawl(self, start="/catalog?page=1", seeds=()):
        if self.obey_robots:
            self.read_robots()
        frontier = deque([(urljoin(self.base, s), 0) for s in (start, *seeds)])
        t0 = time.time()
        while frontier and self.stats["requests"] < self.budget:
            url, depth = frontier.popleft()
            if url in self.seen or not url.startswith(self.base):
                continue
            self.seen.add(url)
            if not self.allowed(url):
                self.stats["skipped_by_policy"] += 1
                continue
            r = self.fetch(url)
            path = urlparse(url).path
            if path.startswith("/maze/"):
                self.stats["maze_requests"] += 1
            if r.status_code != 200:
                continue
            if "Content-Usage" in r.headers and self.obey_robots and not self.licensed:
                key = {"ai-train": "train-ai", "ai-input": "ai-use", "search": "search"}[self.purpose]
                if f"{key}=n" in r.headers["Content-Usage"].replace(" ", ""):
                    self.stats["stopped_by_content_usage"] += 1
                    break
            if is_maze_page(r):
                for href, hidden in extract_links(r.text):
                    frontier.append((urljoin(url, href), depth + 1))
                continue
            ctype = r.headers.get("content-type", "")
            if "html" in ctype:
                self.skus.update(SKU_RE.findall(r.text))
                for href, hidden in extract_links(r.text):
                    if hidden and not self.follow_hidden:
                        self.stats["ignored_hidden_links"] += 1
                        continue
                    frontier.append((urljoin(url, href), depth + 1))
            elif "json" in ctype:
                for p in r.json().get("products", []):
                    self.skus.add(p["sku"])
            elif "xml" in ctype:
                self.skus.update(SKU_RE.findall(r.text))
            elif "markdown" in ctype:
                self.skus.update(MD_SKU.findall(r.text))
        self.stats["seconds"] = round(time.time() - t0, 1)
        return self.report()

    def report(self):
        skus = {s for s in self.skus if re.fullmatch(r"p\d{3}", s)}
        out = {"label": self.label, "requests": self.stats["requests"], "products": len(skus),
               "coverage": round(len(skus) / CATALOGUE_SIZE, 3), "maze_pages": self.stats["maze_pages"],
               "status": {k: v for k, v in self.stats.items() if k.isdigit()},
               "charged_pages": self.stats["charged"], "spent_usd": round(self.spent, 2),
               "seconds": self.stats["seconds"]}
        for k in ("skipped_by_policy", "stopped_by_content_usage", "ignored_hidden_links", "errors"):
            if self.stats[k]:
                out[k] = self.stats[k]
        return out


def print_report(rep):
    print(f"  [{rep['label']}] {rep['requests']} requests in {rep['seconds']}s -> "
          f"{rep['products']}/{CATALOGUE_SIZE} products ({rep['coverage']:.0%}), maze pages {rep['maze_pages']}, "
          f"charged {rep['charged_pages']} (${rep['spent_usd']:.2f}), statuses {rep['status']}")
    extras = {k: v for k, v in rep.items() if k in ("skipped_by_policy", "stopped_by_content_usage",
                                                    "ignored_hidden_links", "errors")}
    if extras:
        print(f"      {extras}")
