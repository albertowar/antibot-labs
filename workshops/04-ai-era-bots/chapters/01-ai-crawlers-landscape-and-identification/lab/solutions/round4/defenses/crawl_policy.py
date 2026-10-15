"""Round 4 (reference solution): identity x purpose -> what the store does.

Rounds 1-3 produced labels. Until now defenses/crawl.py's default mapping turned them into
allow or block, which is wrong in both directions: it blocks a small search engine that
merely cannot prove itself, and it serves a verified training crawler as if "verified" meant
"welcome". From Round 4 the earlier layers only label and this check decides.

decide() receives:
    identity    browser-like | declared-unchecked | declared-verified | impersonator |
                declared-unverifiable | declared-unlisted | undeclared-crawler
    purpose     search | training | user-action | agent | mixed | undeclared | ""
    robots_ok   what our robots.txt says to this token for this path
    score       the Round 3 behaviour score (0 for verified crawlers and impersonators)
    page_rate   this address's catalog page requests in the current minute

and returns one of allow / limit / challenge / block, or None to keep the default
mapping. Limit means "serve within a budget, 429 beyond it"; challenge means "ask for
proof first" (this chapter registers a challenge nobody can solve, so a challenge reads as a
403 "challenged" on the scoreboard; a gate that can be earned is a later chapter's job).
Only block is a hard no.

Questions the policy must answer explicitly:
  * A verified training crawler on a page robots.txt disallows: it is ignoring the
    policy it is documented to honour. What now?
  * A search engine nobody can verify: is "we can't tell" a reason to refuse?
  * An undeclared crawler: block, or make it prove something?

False-positive profile: "limit" is friction you chose on purpose (the small search engine
gets a budget, not a ban); "block" on an unverifiable crawler is how you lose your search
traffic to a competitor that happens to be new.
"""

from __future__ import annotations

from . import crawl
from .crawl import (  # noqa: F401  (the vocabulary decide() speaks, re-exported for your convenience)
    ALLOW, BLOCK, BROWSER_LIKE, CHALLENGE, DECLARED_UNCHECKED, DECLARED_UNLISTED, DECLARED_UNVERIFIABLE,
    DECLARED_VERIFIED, IMPERSONATOR, LIMIT, UNDECLARED_CRAWLER, Decision, allow, block, challenge, limit)
from .pipeline import Check

UNVERIFIABLE_BUDGET = 10      # page requests per minute per address
USER_ACTION_BUDGET = 30


def decide(identity: str, purpose: str, robots_ok: bool, score: float, page_rate: int) -> Decision | None:
    if identity == IMPERSONATOR:
        return block("claims a token from an address the operator does not publish")

    if identity == DECLARED_VERIFIED:
        if not robots_ok:
            return block("verified crawler ignoring our robots.txt")
        if purpose == "user-action" and page_rate > USER_ACTION_BUDGET:
            return limit("user-triggered fetcher over budget")
        return allow(f"verified {purpose} crawler")

    if identity in (DECLARED_UNVERIFIABLE, DECLARED_UNLISTED, DECLARED_UNCHECKED):
        if not robots_ok:
            return block("robots.txt disallows this token here")
        if page_rate > UNVERIFIABLE_BUDGET:
            return limit("unverifiable crawler over budget")
        return allow("unverifiable crawler within budget")

    if identity == UNDECLARED_CRAWLER:
        return challenge(f"crawler behaviour from an undeclared client (score {score:.0f})")

    return allow("")


def _check(ctx):
    """Given: ask decide(); None falls back to the blunt Round 3 mapping."""
    if not crawl.is_page(ctx):
        return None
    st = crawl.state(ctx)
    d = decide(identity=st["identity"], purpose=st["purpose"], robots_ok=st["robots_ok"],
               score=st["score"], page_rate=crawl.page_rate(ctx))
    if d is None:
        d = crawl.default_action(ctx.level, st["identity"], st["robots_ok"], st["score"], 60)
    return crawl.answer(ctx, d)


CHECK = Check("crawl_policy", _check)
