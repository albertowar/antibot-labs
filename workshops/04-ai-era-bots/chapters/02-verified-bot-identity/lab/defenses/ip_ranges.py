"""Operator-published IP ranges, and what a match is worth.

Operators that run no reverse DNS (OpenAI, Anthropic, Perplexity) and some that do (Google,
Bing) publish JSON files of the prefixes their crawlers use. Same shape everywhere, modelled on
Google's:

    {"creationTime": "2026-10-08T00:00:00Z",
     "prefixes": [{"ipv4Prefix": "203.0.113.4/30"}, {"ipv6Prefix": "2001:db8::/48"}]}

W1 Ch3 built the same index for cloud-provider ranges. Three things are different for crawlers:

  * **Freshness.** Operators add prefixes without notice. A vendored copy (VENDORED_SNAPSHOT
    below is "what someone pasted in last quarter") silently rejects every crawler on a new
    prefix, which is a false positive you only find when a search team asks why indexing
    dropped. Fetch on a schedule, cache with a TTL, and keep the last good copy as a fallback
    for when the fetch fails.
  * **A range names a network, not a program.** Google's user-triggered fetchers include App
    Engine egress: any tenant's app can make requests from those addresses, with any
    User-Agent. Anthropic's single list covers three bots. Verification tells you *whose
    network*; entitlement is a separate decision.
  * **Category, not identity, decides the lane.** User-triggered fetchers act for one person and
    ignore robots.txt, so they get a person's budget. Shared infrastructure gets nothing beyond
    what any client gets.

The lab's operators run on addresses from the store's own cloud pools (data/world.json:
`cloud_gcp` for Google, Bing and Apple, `cloud_vm` for OpenAI, Anthropic, Perplexity and the
shared "App Engine" slice). That is the point: the edge rents those pools to anyone, so the pool
proves nothing and only the operator's published list can say who is who.

Enabled at DEFENSE_LEVEL >= 3.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

import httpx
import labnet

from .operators import CRAWLER_LANE_CATEGORIES, OPERATORS

RANGE_TTL_S = 3600          # how long a fetched list is trusted before refetching
FETCH_TIMEOUT_S = 2.0
CACHE_PREFIX = "lab:ch2:ranges:"      # under lab:*, so POST /lab/reset clears it

# "Pasted in last quarter": the snapshot a stub ships with. gptbot.json is missing the
# 203.0.113.8/30 prefix OpenAI added since.
VENDORED_SNAPSHOT: dict[str, list[str]] = {
    "google/common-crawlers.json": ["198.51.100.96/30"],
    "google/user-triggered-fetchers.json": ["203.0.113.48/28"],
    "bing/bingbot.json": ["198.51.100.100/30"],
    "openai/gptbot.json": ["203.0.113.4/30"],
    "openai/searchbot.json": ["203.0.113.12/30"],
    "openai/chatgpt-user.json": ["203.0.113.16/29"],
    "anthropic/bots.json": ["203.0.113.24/29"],
    "perplexity/perplexitybot.json": ["203.0.113.32/31"],
}


@dataclass
class RangeHit:
    list_path: str
    operator: str
    prefix: str


def mock_url() -> str:
    """The side service that plays the operators' websites (guarded: it must be this machine)."""
    return labnet.target("MOCK_URL", "http://127.0.0.1:5001")


def _parse(doc: dict) -> list[str]:
    return [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in doc.get("prefixes", [])
            if p.get("ipv4Prefix") or p.get("ipv6Prefix")]


def load(list_path: str, r) -> list[str]:
    """Return the prefixes for one published file.

    Round 3b: fetch the live copy from f"{mock_url()}/ranges/{list_path}" (production: the
    operator's URL), parse it with _parse(), cache it in `r` under CACHE_PREFIX + list_path for
    RANGE_TTL_S, keep a "last good" copy without TTL as the fallback, and only then fall back
    to the snapshot.
    """
    # TODO (Round 3b): live fetch with a TTL cache and a last-good fallback.
    return VENDORED_SNAPSHOT.get(list_path, [])


def lookup(ip: str, r) -> RangeHit | None:
    """Which operator's published file contains `ip`, if any.

    Round 3a: walk OPERATORS[*]["ranges"], load() each file, and return a RangeHit for the
    first prefix that contains `ip` (ipaddress.ip_network(prefix, strict=False)).
    """
    # TODO (Round 3a): prefix lookup across every operator's published files.
    return None


def lane_for(claim: str, method: str, op: dict) -> tuple[str, str]:
    """Entitlement: which lane does a *verified* identity get, and why.

    Round 3c: shared infrastructure (op.get("shared_infra")) and categories outside
    CRAWLER_LANE_CATEGORIES get the anonymous lane. Say why in the reason string.
    """
    # TODO (Round 3c): scope the entitlement by category and shared infrastructure.
    return "verified", f"{claim} verified via {method}: any verified identity gets the crawler lane"
