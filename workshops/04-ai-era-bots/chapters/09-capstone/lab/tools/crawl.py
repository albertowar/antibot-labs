"""
W4 Ch9 Capstone — shared crawler engine and Web Bot Auth signer (from W4 Ch3)

Used by both sides: tools/legit_traffic.py drives the verified search crawler,
the licensed (paying) crawler and the prefetching browsers with it, and
attacks/round1_crawler_fleet.py drives the impostors. The ethics guardrail is
built in: a non-loopback target raises before a single request is sent.

The IPs are RFC 5737 documentation ranges, honoured by the store only from
loopback (X-Lab-Egress). 203.0.113.0/26 and /26+64 are the two lab crawler
operators' *published* ranges (defenses/crawler_registry.py); 192.0.2.0/24 is
"a datacenter nobody published"; the rest of 198.51.100.0/24 and
203.0.113.0/24 is "residential".

``Crawler`` is a deliberately simple breadth-first fetcher: a frontier, a page
budget, link extraction with the stdlib HTML parser, and hooks for the choices
each round makes (obey robots.txt or not, sign or not, pay or not, follow
hidden links or not). Just strong enough to beat the previous round.
"""

import base64
import ipaddress
import os
import re
import secrets
import time
import urllib.robotparser
from collections import Counter, deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
KEYS = os.path.join(LAB_DIR, "attacks", "keys")
BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:8409").rstrip("/")
CATALOGUE_SIZE = 120

TRAINBOT_UA = "Mozilla/5.0 (compatible; LabTrainBot/1.0; +https://trainbot.example/bot)"
SEARCHBOT_UA = "Mozilla/5.0 (compatible; LabSearchBot/2.1; +https://labsearch.example/bot)"
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; LabSearchBot/2.1; +https://labsearch.example/bot) impostor"
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/150.0.0.0 Safari/537.36")
BROWSER_HEADERS = {"Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

TRAINBOT_RANGE = [f"203.0.113.{i}" for i in range(1, 63)]      # published
SEARCHBOT_RANGE = [f"203.0.113.{i}" for i in range(65, 127)]   # published
DATACENTER = [f"192.0.2.{i}" for i in range(1, 200)]           # unpublished cloud
RESIDENTIAL = [f"198.51.100.{i}" for i in range(1, 255)]

SKU_RE = re.compile(r"/product/([a-z0-9\-]+)")
MD_SKU = re.compile(r"\b(cat-\d{3})\b")


def require_local(url):
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url
    except ValueError:
        pass
    raise SystemExit(f"Refusing to run against non-local target {host!r}. This lab only ever targets the "
                     f"local demo store (127.0.0.1). Do not remove this check to 'try it on something real'.")


class Signer:
    """Signs requests the way a registered crawler operator would (RFC 9421, Ed25519, Web Bot Auth tag)."""

    def __init__(self, pem_name, keyid, signature_agent):
        from cryptography.hazmat.primitives import serialization
        with open(os.path.join(KEYS, pem_name), "rb") as fh:
            self.key = serialization.load_pem_private_key(fh.read(), password=None)
        self.keyid, self.agent = keyid, signature_agent

    def headers(self, authority):
        now = int(time.time())
        params = (f'("@authority" "signature-agent");created={now};expires={now + 300};'
                  f'nonce="{secrets.token_hex(8)}";keyid="{self.keyid}";alg="ed25519";tag="web-bot-auth"')
        base = "\n".join([f'"@authority": {authority}', f'"signature-agent": {self.agent}',
                          f'"@signature-params": {params}']).encode()
        sig = base64.b64encode(self.key.sign(base)).decode()
        return {"Signature-Agent": self.agent, "Signature-Input": f"sig1={params}", "Signature": f"sig1=:{sig}:"}


def trainbot_signer():
    return Signer("trainbot_ed25519.pem", "trainbot-2026-10", "https://trainbot.example")


def searchbot_signer():
    return Signer("searchbot_ed25519.pem", "searchbot-2026-10", "https://labsearch.example")


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
        self.base = require_local(base).rstrip("/")
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
        h = {"User-Agent": self.ua, "X-Lab-Egress": self._ip(), "X-Lab-Actor": self.actor,
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
        skus = {s for s in self.skus if s.startswith("cat-")}
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
