"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement are absolute: these scripts run ONLY against the local demo
store you run yourself. ``require_local`` enforces it in code — a non-loopback
target raises before a single request is sent. Lab traffic never touches a third
party, a public proxy, or anyone else's infrastructure. Every account, review,
IP and session here is synthetic, and the "LLM" is a local mock unless you
point LLM_URL at a model running on your own machine.

The IPs below are RFC 5737 documentation ranges. They are not real hosts; the
store only honours them from loopback, to stand in for the egress a real attacker
would rent. The point of the lab is to train defenders against your own app.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA = os.path.join(LAB_DIR, "data")
sys.path.insert(0, LAB_DIR)   # tools.llm, defenses.challenge_gate (pow helper)

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")

RESIDENTIAL = [f"198.51.100.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(1, 255)]
DATACENTER = [f"192.0.2.{i}" for i in range(1, 255)]

REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")


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
        f"Refusing to run against non-local target {host!r}. "
        f"This lab only ever targets the local demo store (127.0.0.1). "
        f"Do not remove this check to 'try it on something real'.")


def headers(actor, client_ip, fp="", session="", user="", ua=REAL_UA, round_=None):
    h = {"X-Lab-Actor": actor, "X-Lab-Client-IP": client_ip, "User-Agent": ua}
    if fp:
        h["X-Lab-FP"] = fp
    if session:
        h["X-Lab-Session"] = session
    if user:
        h["X-Lab-User"] = user
    if round_:
        h["X-Lab-Round"] = str(round_)
    return h


_BLOCK_TAGS = {"p", "div", "article", "section", "h1", "h2", "h3", "h4", "li", "ul", "ol",
               "header", "footer", "main", "nav", "tr", "br", "table"}


class _TextExtractor(HTMLParser):
    """What an 'HTML to text' step gives a model: every text node, block
    elements on their own lines, scripts and styles dropped. Hidden or not, it is
    all text to the model — that is the whole of Round 3."""

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
        return "\n".join(re.sub(r"\s+", " ", l) for l in out)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    return p.text()
