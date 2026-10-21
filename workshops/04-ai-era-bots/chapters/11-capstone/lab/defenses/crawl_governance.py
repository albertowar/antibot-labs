"""
W4 Ch11 Capstone — L1 crawl governance: identity × purpose → allow / charge / 402 / maze / block (YOUR CODE, Round 1)

Every content request passes through evaluate(ctx) once the store runs at
DEFENSE_LEVEL >= 1. Below that it runs in shadow: logged, never enforced.

ctx keys (all GIVEN, from W4 Ch1-3 infrastructure):
    identity      crawler_identity.Identity(operator, purpose, verified, how, reason)
    rule          "allow" | "deny" | "licensed" for the identity's purpose, or None
    path          the request path
    disallowed    robots.txt would forbid this path for this crawler (bool)
    egress_kind   "residential" | "datacenter" | "local"
    pages_per_min content pages this egress IP fetched this minute
    maze_tagged   this IP already walked into the maze (bool)
    price         USD per page for licensed purposes
    exact, max    the client's crawler-exact-price / crawler-max-price headers

Return a decision.Decision: allow(), charged(), paywall(), maze(), block().
paywall.evaluate(ctx) implements the 402 exchange for you (W4 Ch3).

The contract (reservation/):
    verified search crawler           allow, always (referrals are revenue)
    verified ai-train crawler         licensed: 402 price discovery, charged when it pays
    verified crawler in a trap path   block (it ignored a Disallow it read)
    declared but unverified crawler   block (can't trust, bill or complain)
    undeclared client                 allow, unless a datacenter egress crawling fast,
                                      then the maze (Ch10 §10.3.3: decoys only for refused traffic)

`tools/checkpoint.py --round 1 --catch-up` drops in the reference.
"""

from . import paywall
from .decision import allow, block, maze

STEALTH_PAGES_PER_MIN = 30   # undeclared + datacenter + above this -> maze


def evaluate(ctx):
    ident = ctx["identity"]
    if ctx["maze_tagged"]:
        return maze(f"{ctx['egress_kind']} client already in the maze: catalogue dark")
    # TODO (Round 1): verified crawlers: allow search, 402 for licensed purposes
    # (paywall.evaluate), block in trap paths and when the rule is "deny".
    # TODO (Round 1): declared-but-unverified crawlers: block.
    # TODO (Round 1): undeclared datacenter clients above STEALTH_PAGES_PER_MIN: maze.
    return allow("crawl governance not wired: everything served free")
