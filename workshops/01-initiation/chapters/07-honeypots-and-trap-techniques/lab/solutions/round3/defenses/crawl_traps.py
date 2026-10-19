"""
crawl_traps (Round 3): three traps for clients that walk the site instead of using it. Each one is a
URL that no person, and no well-behaved crawler, has a reason to request.

  1. Trap link: a link at the foot of every page, hidden by traps.css and taken out of the Tab order.
     A browser user never sees it. A crawler that follows every href in the raw HTML takes it on the
     first page. The archive pages behind it link to more archive pages: a small maze.

  2. Honey record: product HONEY_SKU exists and returns a real-looking page, but no listing, sitemap
     or link mentions it. Only a client that enumerates SKUs past the catalog finds it. It is also a
     canary: if it turns up on a competitor's site, you know where they got their data.

  3. Decoy endpoints: paths scanners always try (/.env, /wp-admin/) and an export URL that only
     appears in a comment in traps.js. Nothing real ever lives there.

robots.txt is what keeps this safe for good crawlers. A search engine that honours `Disallow` never
requests a trap path, so a hit means the client either ignored robots.txt or never read it. Leave a
trap out of robots.txt and you are trapping Googlebot. The store's base policy is untouched; this
module adds its lines through the ext (hooks.robots).

Trade-offs:
  - Listing a trap in robots.txt advertises the path. A bot that reads robots.txt to find interesting
    URLs walks straight in, which is fine. A bot that reads it to stay out also stays out of your
    traps.
  - Crawl traps say nothing about a scraper that renders the page and follows only what a human could
    click.
  - The site's own link prefetching (Speculation Rules with eager document rules, prefetch plugins)
    can request hidden links for real users. Exclude trap URLs from those rules.
  - A crawl-trap hit is a monitor-level signal here, not a block: detection is not prevention. What
    it buys is attribution, a canary in the attacker's dataset and crawl budget wasted in the maze.
"""

from . import responses
from .pipeline import Check

TRAP_LINK_PATH = "/catalog/archive"
HONEY_SKU = "p121"                      # the first SKU after the 120-product catalog
DECOY_PATHS = {"/.env", "/wp-admin", "/wp-admin/", "/wp-login.php"}
DECOY_PREFIXES = ("/api/internal/",)

# Round 3 solution: tell good crawlers where the traps are. A crawler that honours robots.txt never
# takes the trap link or the internal API, so a hit there means the client ignored robots.txt. The
# scanner decoys (/.env, /wp-admin/) stay unlisted: nothing legitimate asks for them either way.
ROBOTS_DISALLOW = [TRAP_LINK_PATH, "/api/internal/"]


def robots_lines(level):
    """Extra robots.txt lines for this level (the ext appends them to the store's base policy)."""
    if level < 3:
        return []
    return [f"Disallow: {path}" for path in ROBOTS_DISALLOW]


def trap_for(path):
    """Return the trap name this path triggers, or None."""
    if path == TRAP_LINK_PATH or path.startswith(TRAP_LINK_PATH + "/"):
        return "trap_link"
    if path in (f"/product/{HONEY_SKU}", f"/api/products/{HONEY_SKU}"):
        return "honey_record"
    if path in DECOY_PATHS or path.startswith(DECOY_PREFIXES):
        return "decoy_endpoint"
    return None


def trap_link_html():
    """The hidden link. Hidden by the .hp class in traps.css."""
    return (f'<a class="hp" href="{TRAP_LINK_PATH}" tabindex="-1" rel="nofollow">'
            "Archived products</a>")


def _check(ctx):
    trap = trap_for(ctx.path)
    if trap:
        return responses.on_hit(ctx, "crawl_traps", trap, ctx.path)
    return None


CHECK = Check("crawl_traps", _check)


if __name__ == "__main__":
    print("robots.txt lines at level 3:", robots_lines(3))
    for path in ["/", "/product/p002", TRAP_LINK_PATH, f"/product/{HONEY_SKU}", "/.env", "/api/internal/export"]:
        print(f"  {path:<24} -> {trap_for(path)}")
