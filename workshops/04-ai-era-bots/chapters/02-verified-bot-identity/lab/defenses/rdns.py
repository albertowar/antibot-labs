"""Reverse DNS verification: the PTR says who owns the address, forward DNS proves it.

The oldest and still most widely documented crawler check (Google, Bing, Apple,
Amazon). Two lookups:

  1. PTR of the source IP -> a hostname. The *owner of the IP block* controls this
     record. For a crawler that is the operator; for a VPS it is whoever rents it,
     and hosting panels let tenants type anything into it ("crawl-1-2-3-4.googlebot.com"
     is a valid PTR string for an attacker's box).
  2. A/AAAA of that hostname -> addresses. The *owner of the domain* controls this.
     An attacker can name their PTR after googlebot.com but cannot make
     googlebot.com resolve that name to their address.

Forward-confirmed reverse DNS (FCrDNS) requires both to agree. Round 1 does step 1
only, which is what a lot of copied snippets do, and Round 2 shows why that is
worthless on its own.

Suffix matching must respect label boundaries: `.googlebot.com` with its leading
dot, or the bare domain. A substring test (`"googlebot.com" in name`) is beaten by
`crawl-1.googlebot.com.attacker.example`.

False positives: operators that publish no reverse DNS (OpenAI, Anthropic,
Perplexity) can never pass; a resolver outage turns every crawler into an
anonymous client; and the check costs one or two DNS round trips, so cache the
verdict per IP. Crawler addresses are stable for hours, so positive verdicts can
live an hour; keep negative verdicts short (minutes) so a fix propagates.

Enabled at DEFENSE_LEVEL >= 1 (suffix) and >= 2 (forward confirmation + cache).
"""

from __future__ import annotations

import json

POSITIVE_TTL_S = 3600
NEGATIVE_TTL_S = 300


def name_matches(name: str, suffixes: list[str]) -> bool:
    """Label-aware suffix match: `x.googlebot.com` matches `.googlebot.com`; `xgooglebot.com` does not."""
    name = name.lower().rstrip(".")
    for suffix in suffixes:
        suffix = suffix.lower()
        if name == suffix.lstrip(".") or name.endswith(suffix):
            return True
    return False


def verify(ip: str, suffixes: list[str], level: int, resolver, r) -> tuple[bool, list[str]]:
    """Return (verified, reasons).

    Round 1: look up the PTR of `ip` with resolver.ptr(ip) and accept it when one name
             passes name_matches(name, suffixes).
    Round 2: when level >= 2, forward-confirm with resolver.a(name) (the result must
             contain `ip`) and cache the verdict in `r` (POSITIVE_TTL_S / NEGATIVE_TTL_S).
    """
    # TODO (Round 1): reverse lookup + suffix match.
    # TODO (Round 2): forward confirmation + cache.
    return False, ["rdns: not implemented"]
