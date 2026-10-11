"""Known-crawler registry (GIVEN infrastructure, not a student exercise).

Workshop 4, Chapter 1 teaches how to *identify* AI crawlers: the user-agent
tokens they declare, the IP ranges and reverse-DNS their operators publish, and
the gap between the two. Workshop 4, Chapter 2 teaches *verified* identity: the
operator publishes an Ed25519 key and signs requests (Web Bot Auth, an IETF
working-group draft built on RFC 9421 HTTP Message Signatures).

This chapter needs both as inputs, so this module is the registry a site would
keep (or buy from its CDN): declared UA token -> operator -> purpose, published
egress ranges, and the operator's public signing key. Two synthetic operators:

    LabTrainBot   trains models        (purpose ai-train)   -- the one we govern
    LabSearchBot  builds a search index (purpose search)    -- the one we must not hurt

Real-world tokens (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot,
Bytespider, ...) belong in Chapter 1's material; they change too often to
hard-code into a lab. The IPs below are RFC 5737 documentation ranges, honoured
by the store only from loopback (X-Lab-Client-IP), standing in for the ranges an
operator would publish.
"""

from __future__ import annotations

import ipaddress
import re

# purpose vocabulary used across the policy, enforcement and paywall modules.
# It matches the IETF AIPREF categories (train-ai, ai-use, search) and the RSL
# usage tokens (ai-train, ai-input, search); the lab uses the RSL spelling.
PURPOSES = ("search", "ai-train", "ai-input")

OPERATORS = {
    "trainbot.example": {
        "ua_token": "LabTrainBot",
        "purpose": "ai-train",
        "ranges": ["203.0.113.0/26"],
        "signature_agent": "https://trainbot.example",
        "keys": {
            "trainbot-2026-10": "Kyxtj5AETd6yOJ1PwGOPCaXr4dCWkx182WakXrn11oo",
        },
    },
    "labsearch.example": {
        "ua_token": "LabSearchBot",
        "purpose": "search",
        "ranges": ["203.0.113.64/26"],
        "signature_agent": "https://labsearch.example",
        "keys": {
            "searchbot-2026-10": "kMT0BDo6Hd3ptXxForG9QZ99WrndD340glGglB3is3I",
        },
    },
}

_BY_TOKEN = {op["ua_token"].lower(): (name, op) for name, op in OPERATORS.items()}
_BY_AGENT = {op["signature_agent"]: (name, op) for name, op in OPERATORS.items()}

_BROWSER_RE = re.compile(r"Mozilla/5\.0 .*(Chrome|Safari|Firefox|Edg)/", re.I)
_TEXT_BROWSER_RE = re.compile(r"^(Lynx|w3m|ELinks|Links)\b", re.I)


def operator_for_ua(user_agent: str):
    """Return (operator_name, record) if the UA declares a registered crawler."""
    ua = (user_agent or "").lower()
    for token, hit in _BY_TOKEN.items():
        if token in ua:
            return hit
    return None, None


def operator_for_agent(signature_agent: str):
    agent = (signature_agent or "").strip().strip('"')
    return _BY_AGENT.get(agent, (None, None))


def classify_ua(user_agent: str) -> str:
    """Coarse UA class for logging and policy: declared crawler, browser, or other.

    'other' covers text-mode browsers, feed readers, link previewers and every
    tool that never pretended to be Chrome. Treating 'other' as hostile is the
    classic false positive of UA-based policy; the lab's reader cohort tests it.
    """
    name, _ = operator_for_ua(user_agent)
    if name:
        return "declared"
    if _BROWSER_RE.search(user_agent or ""):
        return "browser"
    if _TEXT_BROWSER_RE.search(user_agent or ""):
        return "text-browser"
    return "other"


def ip_in_published_ranges(ip: str, record) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(r) for r in record.get("ranges", []))
