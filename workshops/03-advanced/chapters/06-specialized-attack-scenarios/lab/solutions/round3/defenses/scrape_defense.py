"""Round 3 defense (REFERENCE SOLUTION) — catalogue-coverage + honeypot SKUs.

Economic chokepoint: your proprietary catalogue (prices, assortment). A competitor
scraper wants *coverage* — ideally every product — while a shopper looks at a
handful. That difference in breadth is the signature, and it survives stealth
headers, residential IPs and slow pacing, because coverage is the attacker's goal,
not an artefact of their tooling.

Two signals:
  1. honeypot SKU fetched: these products are never linked from the navigation, so
     a client that requests one found it by enumerating. Instant flag (BLOCK).
  2. session coverage over a window above a human ceiling -> BLOCK (serve a tarpit
     / degraded response in production; here we just refuse).

False positive, named honestly: power users, comparison shoppers and the site's own
search-indexing crawler also have high coverage. Allowlist known-good crawlers by
verified identity (W4 Ch2), and set the ceiling from your real per-session
distribution, not a guess — a hard cap will catch your most engaged customers.
"""

from __future__ import annotations

from store import allow, block, Decision

COVERAGE_CAP = 25   # distinct products+listing pages per session per window


def evaluate(ctx) -> Decision:
    if ctx["honeypot"]:
        return block("fetched a honeypot SKU (only enumeration finds it)", score=100.0)
    if ctx["coverage"] > COVERAGE_CAP:
        return block(f"session coverage {ctx['coverage']} > {COVERAGE_CAP}", score=90.0)
    return allow(f"coverage {ctx['coverage']}")
