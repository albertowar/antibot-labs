"""Round 4 (reference solution): identity x purpose -> what the store does.

Rounds 1-3 produced *labels*. The default mapping in demo_site/app.py turned every
label into allow or block, which is wrong in both directions: it blocks a small search
engine that merely cannot prove itself, and it serves a verified training crawler as if
"verified" meant "welcome". This policy separates the two questions:

    identity   how sure are we who this is   (verified / impersonator / unverifiable / undeclared / browser-like)
    purpose    what they say they will do     (search / training / user-action / agent / undeclared)

and picks from four actions, only one of which is a hard no:

    allow      serve
    limit      serve within a per-minute budget, 429 beyond it  (friction, not refusal)
    challenge  ask for proof before serving                     (W4 Ch3 makes this proof-of-work)
    block      refuse

Rules of thumb encoded below:
  * Block only proven lies (impersonators) and verified crawlers that ignore the policy
    they are documented to honour.
  * Never block on "we can't tell". Unverifiable crawlers get a budget; undeclared
    crawlers get a challenge. Both keep a path open for the honest and make volume
    expensive for the rest.
  * robots.txt is a preference; the policy is where it becomes a decision.
"""

from __future__ import annotations

from collections import namedtuple

# Vocabulary shared with demo_site/store.py (kept inline so this file imports standalone).
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
USER_ACTION_BUDGET = 30       # a person asked for this; be generous, not unlimited


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
