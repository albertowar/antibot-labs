"""
scrape_defense (Round 3, reference): honeypot SKUs and catalogue coverage.

The economics. A scraper profits from COVERAGE of your catalogue; a shopper looks at a handful of
products. That gap survives stealth headers, residential addresses and slow pacing, because coverage
is the attacker's goal, not an artefact of its tooling.

Two signals:
  1. honeypot SKU hit: the product is hidden from listings and the sitemap and linked only by an
     invisible link in the navigation. Only a client that follows every href, or enumerates SKUs, finds
     it. The session is flagged on the first hit, so everything it asks for afterwards is blocked too.
  2. session coverage over a ceiling: distinct products and listing pages per session per window.
     A scraper that learned to skip hidden links (--skip-hidden) is still cut off here.

Who it hurts. Power users, comparison shoppers and your own crawler have high coverage. Set the
ceiling from your real per-session distribution (here: shoppers view 3 to 7 products, the researcher
18), allowlist crawlers by verified identity (W4 Ch2), and prefer a degraded answer (a tarpit, stale
data) to a block when you can: a block tells the scraper which signal caught it. What it misses: a
scraper that rotates sessions below the ceiling; only the honeypot and aggregate coverage per network
or per account see that.
"""

from .pipeline import Check, Signal

COVERAGE_CAP = 25
WINDOW_S = 600


def _check(ctx):
    seen = ctx.attrs.get("catalog")
    if not seen:
        return None
    if ctx.session.get("scraper"):
        return [Signal("scrape", "flagged_session", 100, "session already hit a honeypot")]
    if seen["honeypot"]:
        ctx.session.set("scraper", "1")
        return [Signal("scrape", "honeypot", 100, f"fetched {seen['key']}, which no page shows a person")]
    key = f"lab:cov:{ctx.session.sid}"
    ctx.redis.sadd(key, seen["key"])
    ctx.redis.expire(key, WINDOW_S)
    covered = ctx.redis.scard(key)
    if covered > COVERAGE_CAP:
        return [Signal("scrape", "coverage", 80, f"{covered} distinct items > {COVERAGE_CAP}")]
    return None


CHECK = Check("scrape_defense", _check)
