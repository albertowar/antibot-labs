"""
scrape_defense (Round 3): honeypot SKUs and catalogue coverage.

The economics. A competitor's scraper profits from COVERAGE: your whole catalogue, prices and
stock, on a schedule. A shopper looks at a handful of products. That difference is the signature,
and it survives stealth headers, residential addresses and slow pacing, because coverage is the
attacker's goal rather than an artefact of its tooling.

The facts you get. demo_site/ext/economies.py fills ctx.attrs["catalog"] on every read of a product
or a listing (pages and API alike):

    kind      "product" | "listing"
    key       str   what was looked at, e.g. "sku:p017" or "list:/products:shoes:2:"
    honeypot  bool  the SKU is a honeypot: hidden from listings and the sitemap, reachable only by a
                    link no person sees (a visually hidden link in the page's navigation)

Rules, strongest first (the starter's bands: 75 block):

  1. honeypot hit        -> flag the SESSION (ctx.session.set("scraper", "1")) and block (100). Every later
                            catalogue read of a flagged session is blocked too.
  2. coverage over cap   -> count distinct keys per session in a Redis set with an expiry; above
                            COVERAGE_CAP, block (80). A real distribution beats a round number.

Who it hurts. Comparison shoppers, price trackers and your own search crawler have high coverage:
a hard cap lands on your most engaged customers. The researcher in the population views 18 products
and stays under the cap; raise the cap with care and allowlist crawlers by verified identity (W4 Ch2).
The hidden link must be out of the tab order and hidden from screen readers (the ext does both) and
disallowed in robots.txt, or you trap Googlebot and your keyboard users.

Reference: solutions/round3/defenses/scrape_defense.py (or `checkpoint.py --round 3 --catch-up`)
"""

from .pipeline import Check, Signal

COVERAGE_CAP = 25      # distinct products and listing pages per session per window
WINDOW_S = 600


def _check(ctx):
    seen = ctx.attrs.get("catalog")
    if not seen:
        return None
    # TODO (Round 3): return a list with ONE Signal, else None.
    #   Signal("scrape", "flagged_session", 100, ...)  the session already hit a honeypot
    #   Signal("scrape", "honeypot", 100, ...)         it hit one now (flag the session first)
    #   Signal("scrape", "coverage", 80, ...)          distinct keys in `lab:cov:<sid>` above COVERAGE_CAP
    return None


CHECK = Check("scrape_defense", _check)
