"""Round 1 (reference solution): who claims to be a crawler, and what our robots.txt says to it.

Two questions, both answered from the client's own words:

  identify(user_agent)  -> which registry token the User-Agent carries, who runs it
                           and for what purpose (training, search, user-action, agent).
                           A browser UA returns None. A bot-looking UA that matches no
                           registry entry is "unlisted": declared, but by nobody we know.
  robots_allows(token, path, robots_text) -> what RFC 9309 says this token may fetch here.

Registry = data/robots.json (ai.robots.txt snapshot, 181 AI-related tokens) plus
data/registry_extra.json (search engines, link previewers). Purpose comes from
data/operators.json for the tokens we curate, and from the registry's free-text
"function" field otherwise. That text is community-maintained hearsay: good enough to
*classify*, never enough to *trust*. Nothing here checks whether the claim is true;
that is Round 2.

Trade-off: substring matching is what ai.robots.txt v2.0 itself does (case-insensitive).
It is cheap and catches "GPTBot/1.4" inside a long UA, but a token like "Spider" or
"OpenAI" also matches inside unrelated strings, so the longest, best-anchored match wins.
"""

from __future__ import annotations

import json
import os
import re
from urllib import robotparser

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data")


def _load_json(name):
    with open(os.path.join(DATA, name)) as fh:
        return {k: v for k, v in json.load(fh).items() if not k.startswith("_")}


REGISTRY: dict[str, dict] = {**_load_json("robots.json"), **_load_json("registry_extra.json")}
OPERATORS: dict[str, dict] = _load_json("operators.json")
_TOKENS = [(t.lower(), t) for t in REGISTRY]

# Anything that admits to being automated without naming a registry token.
GENERIC_BOT = re.compile(r"bot\b|bot/|crawl|spider|scrap|fetch|\+https?://", re.I)

# Purpose from the registry's free text, when operators.json has no curated entry.
_PURPOSE_WORDS = [("train", "training"), ("search", "search"), ("index", "search"),
                  ("preview", "user-action"), ("user", "user-action"), ("agent", "agent"),
                  ("assistant", "agent")]


def purpose_of(token: str, entry: dict) -> str:
    op = OPERATORS.get(token)
    if op:
        return op["purpose"]
    text = (entry.get("function", "") + " " + entry.get("description", "")).lower()
    for word, purpose in _PURPOSE_WORDS:
        if word in text:
            return purpose
    return "undeclared"


def identify(user_agent: str) -> dict | None:
    ua = user_agent or ""
    ua_lc = ua.lower()
    best = None
    for lc, token in _TOKENS:
        pos = ua_lc.find(lc)
        if pos < 0:
            continue
        after = ua_lc[pos + len(lc):pos + len(lc) + 1]
        anchored = after in ("", "/", ";", ")", " ", ",")   # "GPTBot/1.4", not "openai.com"
        rank = (anchored, len(lc))
        if best is None or rank > best[0]:
            best = (rank, token)
    if best:
        token = best[1]
        entry = REGISTRY[token]
        return {"token": token, "listed": True,
                "operator": OPERATORS.get(token, {}).get("operator") or entry.get("operator", "?"),
                "purpose": purpose_of(token, entry),
                "respects_robots": entry.get("respect", "Unclear")}
    if GENERIC_BOT.search(ua):
        guess = re.split(r"[/( ;]", ua.strip(), 1)[0] or "unknown-bot"
        return {"token": guess[:40], "listed": False, "operator": "unknown",
                "purpose": "undeclared", "respects_robots": "Unclear"}
    return None


_rp_cache: dict[int, robotparser.RobotFileParser] = {}


def robots_allows(token: str, path: str, robots_text: str) -> bool:
    """RFC 9309 evaluation of our own robots.txt for this token.

    The group whose User-agent line matches the token applies; otherwise the '*'
    group. Python's robotparser does the matching (substring, case-insensitive on the
    product token) and the longest-match rule between Allow and Disallow.
    """
    key = hash(robots_text)
    rp = _rp_cache.get(key)
    if rp is None:
        rp = robotparser.RobotFileParser()
        rp.parse(robots_text.splitlines())
        _rp_cache.clear()
        _rp_cache[key] = rp
    return rp.can_fetch(token, path)
