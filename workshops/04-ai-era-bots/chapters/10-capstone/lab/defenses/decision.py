"""
W4 Ch10 Capstone — the decision vocabulary every layer speaks (GIVEN)

Two families of outcome live in one store:

    content paths (crawl governance, W4 Ch1-3)
        allow     served, free
        charged   served, and a crawl fee was booked to the ledger (402 flow)
        paywall   402 Payment Required with a price, nothing served
        maze      a decoy page instead of content (deterrence, within limits)
        block     403

    actions (agent governance, W4 Ch4-8; same scale as W2 Ch8)
        allow / challenge / block, plus an optional human step-up

``reason`` is for the scoreboard and the debrief. Round 4's oracle guard is
about never sending it to a client.
"""

from collections import namedtuple

ALLOW = "allow"
CHALLENGE = "challenge"
BLOCK = "block"
MAZE = "maze"
PAYWALL = "paywall"
CHARGED = "charged"
INVALID = "invalid"

Decision = namedtuple("Decision", "action score reason charged", defaults=(0.0,))


def allow(reason="", score=0.0):
    return Decision(ALLOW, score, reason)


def challenge(reason, score=0.0):
    return Decision(CHALLENGE, score, reason)


def block(reason, score=0.0):
    return Decision(BLOCK, score, reason)


def maze(reason, score=90.0):
    return Decision(MAZE, score, reason)


def paywall(reason, price):
    return Decision(PAYWALL, 0.0, reason, 0.0 if price is None else float(price))


def charged(reason, price):
    return Decision(CHARGED, 0.0, reason, float(price))
