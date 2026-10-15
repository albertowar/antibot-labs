"""Round 1: who claims to be a crawler, and what does our robots.txt say to it?

Two functions the check below calls on every catalog request once DEFENSE_LEVEL >= 1:

  identify(user_agent) -> dict | None
      {"token": "GPTBot", "listed": True, "operator": "OpenAI", "purpose": "training",
       "respects_robots": "Yes"}  for a registry token found in the UA;
      {"token": <guess>, "listed": False, "operator": "unknown", "purpose": "undeclared", ...}
      for a bot-looking UA that matches no registry entry;
      None for a browser UA.
  robots_allows(token, path, robots_text) -> bool
      what RFC 9309 says this token may fetch here (urllib.robotparser does the rules).

Data you have: REGISTRY (data/robots.json, the ai.robots.txt snapshot, merged with
data/registry_extra.json) and OPERATORS (data/operators.json, with a curated purpose
per token). Nothing here verifies a claim. That is Round 2.

As shipped, identify() recognises nobody, so every client is treated as a browser. Complete
the two TODOs, wire `crawler_registry.CHECK` into LADDER[1] in defenses/ladder.py, then edit
data/crawl_policy.robots to say what each purpose may do (solutions/round1/data/ has one
policy). The check, the labels and the blunt allow-or-block mapping are in defenses/crawl.py.

False-positive profile: a UA match is a claim, not evidence. Substring matching is what
ai.robots.txt v2.0 itself does (case-insensitive); a short token like "Spider" or "OpenAI"
also matches inside unrelated strings, which is why the longest, best-anchored match wins.
"""

from __future__ import annotations

import json
import os
import re
from urllib import robotparser

from . import crawl
from .pipeline import Check

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


def purpose_of(token: str, entry: dict) -> str:
    """Curated purpose when we have one; otherwise a guess from the registry's free text."""
    op = OPERATORS.get(token)
    if op:
        return op["purpose"]
    text = (entry.get("function", "") + " " + entry.get("description", "")).lower()
    for word, purpose in [("train", "training"), ("search", "search"), ("index", "search"),
                          ("preview", "user-action"), ("user", "user-action"), ("agent", "agent")]:
        if word in text:
            return purpose
    return "undeclared"


def identify(user_agent: str) -> dict | None:
    # TODO (Round 1): find the registry token inside the User-Agent.
    #   * Match case-insensitively (ai.robots.txt v2.0 does), and prefer the longest
    #     token that is followed by "/", ";", ")" or the end of the string, so that
    #     "GPTBot/1.4; +https://openai.com/gptbot" resolves to GPTBot, not "OpenAI".
    #   * Return the dict described in the module docstring, using purpose_of().
    #   * If no token matches but GENERIC_BOT does, return the "unlisted" dict.
    #   * Otherwise return None: this is (or claims to be) a browser.
    return None


def robots_allows(token: str, path: str, robots_text: str) -> bool:
    # TODO (Round 1): parse robots_text with urllib.robotparser.RobotFileParser
    #   (rp.parse(robots_text.splitlines())) and return rp.can_fetch(token, path).
    #   Parsing on every request is fine for the lab; cache by hash(robots_text) if
    #   you want the latency to look like production.
    return True


def _check(ctx):
    """Given: run your two functions on the User-Agent and record the claim."""
    if not crawl.is_page(ctx):
        return None
    st = crawl.state(ctx)
    ident = identify(ctx.ua.raw)
    if ident:
        st.update(token=ident["token"], purpose=ident["purpose"], operator=ident["operator"],
                  listed=ident["listed"],
                  identity=crawl.DECLARED_UNCHECKED if ident["listed"] else crawl.DECLARED_UNLISTED)
        st["robots_ok"] = robots_allows(ident["token"], ctx.path, crawl.robots_text())
    return crawl.enforce(ctx)


CHECK = Check("crawler_registry", _check)
