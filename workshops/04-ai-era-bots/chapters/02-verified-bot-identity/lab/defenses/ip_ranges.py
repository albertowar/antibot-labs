"""Operator-published IP ranges, and what a match is worth.

Operators that run no reverse DNS (OpenAI, Anthropic, Perplexity) and some that do
(Google, Bing) publish JSON files of the prefixes their crawlers use. Same shape
everywhere, modelled on Google's:

    {"creationTime": "2026-10-08T00:00:00Z",
     "prefixes": [{"ipv4Prefix": "198.51.100.20/30"}, {"ipv6Prefix": "2001:db8::/48"}]}

Workshop 1, Chapter 2 built the same index for cloud-provider ranges. Three things
are different for crawlers:

  * **Freshness.** Operators add prefixes without notice. A vendored copy
    (VENDORED_SNAPSHOT below is "what someone pasted in last quarter") silently
    rejects every crawler on a new prefix, which is a false positive you only find
    when a search team asks why indexing dropped. Fetch on a schedule, cache with
    a TTL, and keep the last good copy as a fallback for when the fetch fails.
  * **A range names a network, not a program.** Google's user-triggered fetchers
    include App Engine egress: any tenant's app can make requests from those
    addresses, with any User-Agent. Anthropic's single list covers three bots.
    Verification tells you *whose network*; entitlement is a separate decision.
  * **Category, not identity, decides the lane.** User-triggered fetchers act for
    one person and ignore robots.txt, so they get a person's budget. Shared
    infrastructure gets nothing beyond what any client gets.

Enabled at DEFENSE_LEVEL >= 3.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass

import httpx

from operators import CRAWLER_LANE_CATEGORIES, OPERATORS

MOCK_URL = os.environ.get("MOCK_URL", "http://127.0.0.1:5001")
RANGE_TTL_S = 3600          # how long a fetched list is trusted before refetching
FETCH_TIMEOUT_S = 2.0

# "Pasted in last quarter": the snapshot a stub ships with. gptbot.json is missing
# the 198.51.100.24/30 prefix OpenAI added since.
VENDORED_SNAPSHOT: dict[str, list[str]] = {
    "google/common-crawlers.json": ["198.51.100.10/31"],
    "google/user-triggered-fetchers.json": ["203.0.113.0/24"],
    "bing/bingbot.json": ["198.51.100.12/31"],
    "openai/gptbot.json": ["198.51.100.20/30"],
    "openai/searchbot.json": ["198.51.100.28/30"],
    "openai/chatgpt-user.json": ["198.51.100.32/29"],
    "anthropic/bots.json": ["198.51.100.40/29"],
    "perplexity/perplexitybot.json": ["198.51.100.50/31"],
}


@dataclass
class RangeHit:
    list_path: str
    operator: str
    prefix: str


def _parse(doc: dict) -> list[str]:
    return [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in doc.get("prefixes", [])
            if p.get("ipv4Prefix") or p.get("ipv6Prefix")]


def load(list_path: str, r) -> list[str]:
    """Return the prefixes for one published file.

    Round 3b: fetch the live copy from f"{MOCK_URL}/ranges/{list_path}" (production: the
    operator's URL), parse it with _parse(), cache it in `r` for RANGE_TTL_S, keep a
    "last good" copy without TTL as the fallback, and only then fall back to the snapshot.
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
