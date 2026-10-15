"""Known-crawler registry (GIVEN infrastructure, not a student exercise).

W4 Ch1 teaches how to *identify* AI crawlers (declared tokens, published ranges, reverse DNS) and
W4 Ch2 how to *verify* one (Web Bot Auth). This chapter needs both as inputs, so this module is the
registry a site would keep, or buy from its CDN: declared UA token -> operator -> purpose, the
egress ranges the operator publishes, and the origin its signing keys are published under. Two
synthetic operators:

    LabTrainBot   trains models          (purpose ai-train)  -- the one we govern
    LabSearchBot  builds a search index  (purpose search)    -- the one we must not hurt

Real tokens (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, Bytespider, ...) belong in
W4 Ch1; they change too often to hard-code into a lab.

The ranges are lab fixtures. Operators rent from the pools every other lab uses, so a crawler's
egress is an ordinary cloud tenant exactly like the impostor who copies its User-Agent: LabTrainBot
publishes the first /27 of `cloud_vm` (203.0.113.0/27) and LabSearchBot the `cloud_gcp` /27
(198.51.100.96/27). The public keys are *not* here: a signed request is verified against the key
directory the operator publishes under `signature_agent`
(defenses/key_directory.py, served in the lab by the mock internet in tools/mock_internet.py).
"""

from __future__ import annotations

import ipaddress
import re

# Purpose vocabulary used across the policy, enforcement and paywall modules. It matches the IETF
# AIPREF categories (train-ai, ai-use, search) and the RSL usage tokens (ai-train, ai-input, search);
# the lab uses the RSL spelling.
PURPOSES = ("search", "ai-train", "ai-input")

OPERATORS = {
    "trainbot.example": {
        "ua_token": "LabTrainBot",
        "purpose": "ai-train",
        "ranges": ["203.0.113.0/27"],
        "signature_agent": "https://trainbot.example",
    },
    "labsearch.example": {
        "ua_token": "LabSearchBot",
        "purpose": "search",
        "ranges": ["198.51.100.96/27"],
        "signature_agent": "https://labsearch.example",
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
    """Coarse UA class for logging: declared crawler, browser, text browser, or other.

    'other' covers feed readers, link previewers and every tool that never pretended to be Chrome.
    Treating 'other' as hostile is the classic false positive of UA-based policy; the lab's reader
    cohort (Lynx, w3m) tests it.
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
