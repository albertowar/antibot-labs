"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement are absolute: these scripts run ONLY against the local demo store you run yourself.
`tools/labclient.py` asks the lab-root `labnet.py` guard for the store URL (and checks every side-service URL
that is set, `LLM_URL` included), and that guard refuses a non-loopback target before a single request is
sent. Lab traffic never touches a third party, a public proxy, or anyone else's infrastructure. Every
account, review, device and address here is synthetic, and the "LLM" is a local mock unless you point
LLM_URL at a model running on your own machine.

Source addresses are rented from `data/world.json` (RFC 5737 / 3849 documentation ranges) and sent in
`X-Lab-Client-IP`, which the store's edge honours only from loopback and only inside a pool. Each attack
has its own: the review farm rents `cloud_vm`, the puzzle solver `hosting_asn` (both datacenters), and the
extractor and the injector's accounts rent `residential_proxy`, which looks exactly like a person. A
"device" is a `did` cookie; the farm and the solver spread many accounts over three of them.

The attacks are just strong enough to beat the previous round and to teach the detection. They exist to
train defenders against the student's own local app, not to be general-purpose tooling.
"""

import json
import os
import re
import sys
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402  (runs the labnet guard on import)

REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
JSON_HEADERS = [("User-Agent", REAL_UA), ("Accept", "application/json"), ("Content-Type", "application/json")]
PAGE_HEADERS = [("User-Agent", REAL_UA), ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")]

FARM_POOL = world_pool("cloud_vm")[0:3]               # Round 1: a datacenter, three devices
SOLVER_POOL = world_pool("hosting_asn")[0:3]          # Round 2: another datacenter, three devices
EXTRACT_POOL = world_pool("residential_proxy")[0:40]  # Round 3: rented residential egress
MULE_POOL = world_pool("residential_proxy")[40:80]    # Round 4: the injector's accounts, one address each


def bot(actor, ip, device=None):
    """A bot client on a rented address; `device` pins its `did` cookie (many accounts, few devices)."""
    c = LabClient(actor, ip=ip)
    if device:
        c.set_cookie("did", device)
    return c


def finish(out):
    """An attack script's last line: one JSON object with at least attempted and succeeded."""
    print(json.dumps(out))
    return out


def catalogue(n):
    """The first n catalogue products as (sku, name), read the way a scraper would: the JSON API, page by page."""
    items, page = [], 1
    c = LabClient("bot:farm:cat", ip=world_pool("cloud_vm")[3])
    while len(items) < n:
        r = c.get(f"/api/products?page={page}", headers=JSON_HEADERS).json()
        items += [(p["sku"], p["name"]) for p in r["items"]]
        if page >= r["pages"]:
            break
        page += 1
    return items[:n]


_BLOCK_TAGS = {"p", "div", "article", "section", "h1", "h2", "h3", "h4", "li", "ul", "ol",
               "header", "footer", "main", "nav", "tr", "br", "table", "form", "select", "option", "label"}


class _TextExtractor(HTMLParser):
    """What an 'HTML to text' step gives a model: every text node, block elements on their own lines,
    scripts and styles dropped. Hidden or not, it is all text to the model: that is the whole of Round 3."""

    def __init__(self):
        super().__init__()
        self.lines = [[]]
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag in _BLOCK_TAGS:
            self.lines.append([])

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        if tag in _BLOCK_TAGS:
            self.lines.append([])

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.lines[-1].append(data.strip())

    def text(self):
        out = [" ".join(parts) for parts in self.lines if parts]
        return "\n".join(re.sub(r"\s+", " ", line) for line in out)


def html_to_text(html):
    p = _TextExtractor()
    p.feed(html)
    return p.text()
