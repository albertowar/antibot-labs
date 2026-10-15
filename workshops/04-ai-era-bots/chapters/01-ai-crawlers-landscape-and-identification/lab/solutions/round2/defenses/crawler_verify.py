"""Round 2: is the crawler who it says it is?

The check below calls verify(ip, token) for every catalog request whose User-Agent carries a
*listed* registry token (DEFENSE_LEVEL >= 2). Return (verdict, method):

    ("verified", "ranges")       ip is inside the operator's published prefixes
    ("verified", "rdns")         forward-confirmed reverse DNS matched a documented suffix
    ("impersonator", <method>)   the operator documents a method and the claim failed it
    ("unverifiable", "none")     the operator documents no method at all

OPERATORS (data/operators.json) tells you, per token, which range file to load from
data/published_ranges/ and which hostname suffixes count. The DNS stand-ins are
defenses/netdb.py: netdb.ptr(ip) is socket.gethostbyaddr(ip)[0], netdb.forward(name)
is socket.gethostbyname_ex(name)[2], both answered from data/rdns.json.

Note what the lab does NOT do: it does not tell operators apart by which network an address
is in. An operator crawler is a tenant of an ordinary cloud pool in data/world.json, exactly
like the attacker who impersonates it. The only difference is what each can prove. Signed
requests (Web Bot Auth, RFC 9421) are the stronger proof and are W4 Ch2's subject.

This is the reference solution. In the student copy every claim is "unverifiable", which
the check treats as "take their word for it": that is how the Round 1 impersonator gets a
free pass. Costs: ranges are a cached file read, FCrDNS is two DNS round trips per new
address (cache by address, as production does).

False-positive profile: a stale range file turns a real crawler into an "impersonator" the
day the operator adds a prefix (the lab's Googlebot sits just outside its snapshot, so only
FCrDNS saves it). Neither method proves purpose: a verified GPTBot is still a training crawler.
"""

from __future__ import annotations

import ipaddress
import json
import os

from . import crawl, netdb
from .crawler_registry import OPERATORS
from .pipeline import Check

HERE = os.path.dirname(os.path.abspath(__file__))
RANGES_DIR = os.path.join(os.path.dirname(HERE), "data", "published_ranges")


def load_prefixes(filename: str) -> list:
    """Parse an operator's range file into ip_network objects.

    Two shapes exist in the wild: {"prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}
    (OpenAI, Google) and a bare list of CIDR strings. Handle both.
    """
    with open(os.path.join(RANGES_DIR, filename)) as fh:
        doc = json.load(fh)
    items = doc.get("prefixes", []) if isinstance(doc, dict) else doc
    nets = []
    for item in items:
        cidr = (item.get("ipv4Prefix") or item.get("ipv6Prefix")) if isinstance(item, dict) else item
        if cidr:
            nets.append(ipaddress.ip_network(cidr, strict=False))
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
    op = OPERATORS.get(token)
    if not op or (not op.get("ranges") and not op.get("rdns")):
        return "unverifiable", "none"
    if op.get("ranges") and in_published_ranges(ip, op["ranges"]):
        return "verified", "ranges"
    if op.get("rdns") and fcrdns(ip, op["rdns"]):
        return "verified", "rdns"
    return "impersonator", "ranges" if op.get("ranges") else "rdns"


_IDENTITY = {"verified": crawl.DECLARED_VERIFIED, "impersonator": crawl.IMPERSONATOR,
             "unverifiable": crawl.DECLARED_UNVERIFIABLE}


def _check(ctx):
    """Given: verify every claim that names a listed token."""
    if not crawl.is_page(ctx):
        return None
    st = crawl.state(ctx)
    if st["listed"] and st["identity"] == crawl.DECLARED_UNCHECKED:
        verdict, st["method"] = verify(ctx.ip, st["token"])
        st["identity"] = _IDENTITY[verdict]
    return crawl.enforce(ctx)


CHECK = Check("crawler_verify", _check)
