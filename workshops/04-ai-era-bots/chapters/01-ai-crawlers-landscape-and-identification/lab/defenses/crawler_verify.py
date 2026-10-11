"""Round 2: is the crawler who it says it is?

The store calls verify(ip, token) for every page request whose User-Agent carries a
*listed* registry token (DEFENSE_LEVEL >= 2). Return (verdict, method):

    ("verified", "ranges")       ip is inside the operator's published prefixes
    ("verified", "rdns")         forward-confirmed reverse DNS matched a documented suffix
    ("impersonator", <method>)   the operator documents a method and the claim failed it
    ("unverifiable", "none")     the operator documents no method at all

OPERATORS (data/operators.json) tells you, per token, which range file to load from
data/published_ranges/ and which hostname suffixes count. The DNS stand-ins are
defenses/netdb.py: netdb.ptr(ip) is socket.gethostbyaddr(ip)[0], netdb.forward(name)
is socket.gethostbyname_ex(name)[2].

As shipped, every claim is "unverifiable", which the store treats as "take their word
for it". That is how the Round 1 impersonator gets a free pass.
"""

from __future__ import annotations

import ipaddress
import json
import os

from defenses import netdb
from defenses.crawler_registry import OPERATORS

HERE = os.path.dirname(os.path.abspath(__file__))
RANGES_DIR = os.path.join(os.path.dirname(HERE), "data", "published_ranges")


def load_prefixes(filename: str) -> list:
    """Parse an operator's range file into ip_network objects.

    Two shapes exist in the wild: {"prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}
    (OpenAI, Google) and a bare list of CIDR strings. Handle both.
    """
    with open(os.path.join(RANGES_DIR, filename)) as fh:
        doc = json.load(fh)
    # TODO (Round 2): turn doc into a list of ipaddress.ip_network(...) objects.
    return []


def in_published_ranges(ip: str, filename: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in load_prefixes(filename))


def fcrdns(ip: str, suffixes: list[str]) -> bool:
    # TODO (Round 2): forward-confirmed reverse DNS.
    #   1. name = netdb.ptr(ip); no PTR -> False
    #   2. name must equal a suffix or end with "." + suffix
    #   3. ip must be in netdb.forward(name)   <- the step a fake PTR cannot pass
    return False


def verify(ip: str, token: str) -> tuple[str, str]:
    op = OPERATORS.get(token)
    if not op or (not op.get("ranges") and not op.get("rdns")):
        return "unverifiable", "none"
    # TODO (Round 2): try ranges first (cheap), then FCrDNS; anything else is an impersonator.
    return "unverifiable", "none"
