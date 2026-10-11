"""Round 4: identity x purpose -> what the store does.

Rounds 1-3 produced labels. Until now the store's default mapping (demo_site/app.py,
default_action) turned them into allow or block, which is wrong in both directions:
it blocks a small search engine that merely cannot prove itself, and it serves a
verified training crawler as if "verified" meant "welcome".

decide() receives:
    identity    browser-like | declared-unchecked | declared-verified | impersonator |
                declared-unverifiable | declared-unlisted | undeclared-crawler
    purpose     search | training | user-action | agent | mixed | undeclared | ""
    robots_ok   what our robots.txt says to this token for this path
    score       the Round 3 behaviour score (0 for verified crawlers and impersonators)
    page_rate   this address's page requests in the current minute

and returns one of allow / limit / challenge / block, or None to keep the default
mapping. Limit means "serve within a budget, 429 beyond it"; challenge means "ask for
proof first" (W4 Ch3 turns it into a proof-of-work gate). Only block is a hard no.

Questions the policy must answer explicitly:
  * A verified training crawler on a page robots.txt disallows: it is ignoring the
    policy it is documented to honour. What now?
  * A search engine nobody can verify: is "we can't tell" a reason to refuse?
  * An undeclared crawler: block, or make it prove something?
"""

from __future__ import annotations

from collections import namedtuple

ALLOW, LIMIT, CHALLENGE, BLOCK = "allow", "limit", "challenge", "block"
BROWSER_LIKE, DECLARED_UNCHECKED, DECLARED_VERIFIED = "browser-like", "declared-unchecked", "declared-verified"
IMPERSONATOR, DECLARED_UNVERIFIABLE, DECLARED_UNLISTED = "impersonator", "declared-unverifiable", "declared-unlisted"
UNDECLARED_CRAWLER = "undeclared-crawler"
Decision = namedtuple("Decision", "action reason")


def allow(reason=""):
    return Decision(ALLOW, reason)


def limit(reason):
    return Decision(LIMIT, reason)


def challenge(reason):
    return Decision(CHALLENGE, reason)


def block(reason):
    return Decision(BLOCK, reason)


UNVERIFIABLE_BUDGET = 10      # page requests per minute per address
USER_ACTION_BUDGET = 30


def decide(identity: str, purpose: str, robots_ok: bool, score: float, page_rate: int) -> Decision | None:
    # TODO (Round 4): replace the default mapping. Returning None keeps Round 3's
    #   blunt allow/block behaviour, which the checkpoint will report as a false
    #   positive on the unverifiable search engine.
    return None
