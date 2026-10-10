"""Round 3 defense (YOUR CODE) — catalogue-coverage + honeypot SKUs.

attacks/round3_scraper.py walks the whole catalogue breadth-first. Rate limiting
barely dents it once it paces itself and rotates egress. But a scraper's goal is
*coverage*, and a shopper's is not — that gap is the signal, and it survives
stealth headers and residential IPs.

ctx keys:
    sku      : str | None -- the product being fetched (None for a listing page)
    honeypot : bool       -- is this SKU a honeypot (never linked in the nav)?
    coverage : int        -- distinct products+listing pages this session has hit

Return BLOCK (or a tarpit in production) when a session behaves like an enumerator.
`python tools/checkpoint.py --round 3 --catch-up` drops in the reference solution.
"""

from __future__ import annotations

from store import allow, Decision

COVERAGE_CAP = 25


def evaluate(ctx) -> Decision:
    # TODO (Round 3):
    #   1. if ctx["honeypot"]: return block(...)   # only a scraper finds these
    #   2. if ctx["coverage"] > COVERAGE_CAP: return block(...)  # breadth tell
    return allow("served (no coverage checks wired yet)")
