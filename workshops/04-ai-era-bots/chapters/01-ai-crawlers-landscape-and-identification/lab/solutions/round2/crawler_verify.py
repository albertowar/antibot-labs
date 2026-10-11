"""Round 2 (reference solution): is the crawler who it says it is?

A User-Agent is a claim. Operators give you two ways to check it:

  1. Published address ranges. OpenAI, Anthropic, Perplexity, Google and Common Crawl
     each publish a JSON file of prefixes (data/operators.json has the real URLs;
     data/published_ranges/ holds lab snapshots in the same shape). Match the source
     address against the prefixes. Fast, offline, and only as fresh as your copy.
  2. Forward-confirmed reverse DNS (FCrDNS). Google, Bing and Common Crawl document a
     hostname suffix. Look up the PTR for the address, check the suffix, resolve that
     name forward, and require the original address in the answer. The forward step is
     what stops a hosting customer who set a googlebot.com-looking PTR on their own box.

Verdicts:
  verified      the claim checks out by one of the operator's documented methods
  impersonator  the operator documents a method and the claim fails it
  unverifiable  the operator documents nothing (small search engines, Bytespider,
                meta-externalagent, every unlisted bot): identifiable, never provable

Trade-offs: a stale range file turns a real crawler into an "impersonator" the day the
operator adds a prefix (refresh daily; log, don't block, on first sight). FCrDNS costs
two DNS round-trips per new address (cache by address). Neither proves purpose: a
verified GPTBot is still a training crawler, which is what robots.txt is for.
"""

from __future__ import annotations

import ipaddress
import json
import os

from defenses import netdb
from defenses.crawler_registry import OPERATORS

HERE = os.path.dirname(os.path.abspath(__file__))
RANGES_DIR = os.path.join(os.path.dirname(HERE), "data", "published_ranges")
_prefix_cache: dict[str, list] = {}


def load_prefixes(filename: str) -> list:
    """Parse an operator's range file. Tolerates the two shapes in the wild:
    {"prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]} and a bare list of CIDRs."""
    if filename in _prefix_cache:
        return _prefix_cache[filename]
    with open(os.path.join(RANGES_DIR, filename)) as fh:
        doc = json.load(fh)
    items = doc.get("prefixes", []) if isinstance(doc, dict) else doc
    nets = []
    for item in items:
        cidr = (item.get("ipv4Prefix") or item.get("ipv6Prefix")) if isinstance(item, dict) else item
        if cidr:
            nets.append(ipaddress.ip_network(cidr, strict=False))
    _prefix_cache[filename] = nets
    return nets


def in_published_ranges(ip: str, filename: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in load_prefixes(filename))


def fcrdns(ip: str, suffixes: list[str]) -> bool:
    """Forward-confirmed reverse DNS, as Google documents it for Googlebot."""
    name = netdb.ptr(ip)                       # socket.gethostbyaddr(ip)[0] in production
    if not name:
        return False
    if not any(name == s or name.endswith("." + s) for s in suffixes):
        return False
    return ip in netdb.forward(name)           # socket.gethostbyname_ex(name)[2]


def verify(ip: str, token: str) -> tuple[str, str]:
    """Return (verdict, method) for a request from ip claiming token."""
    op = OPERATORS.get(token)
    if not op or (not op.get("ranges") and not op.get("rdns")):
        return "unverifiable", "none"
    if op.get("ranges") and in_published_ranges(ip, op["ranges"]):
        return "verified", "ranges"
    if op.get("rdns") and fcrdns(ip, op["rdns"]):
        return "verified", "rdns"
    return "impersonator", "ranges" if op.get("ranges") else "rdns"
