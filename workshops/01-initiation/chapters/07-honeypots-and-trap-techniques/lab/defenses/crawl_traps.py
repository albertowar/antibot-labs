"""
Chapter 7 — Crawl Traps (Section 7.3)

Three traps for clients that walk the site instead of using it. Each one is a
URL that no person, and no well-behaved crawler, has a reason to request.

  1. Trap link: a link in the catalog footer, hidden by store.css and taken out
     of the Tab order. A browser user never sees it. A crawler that follows
     every href in the raw HTML takes it on the first page.

  2. Honey record: product HONEY_PRODUCT_ID exists and returns a real-looking
     product, but no page links to it. Only a client that enumerates ids finds
     it. It is also a canary: if it turns up on a competitor's site, you know
     where they got their data.

  3. Decoy endpoints: paths scanners always try (/.env, /wp-admin/) and an
     export URL that only appears in a comment in store.js. Nothing real ever
     lives there.

robots.txt is what keeps this safe for good crawlers. A search engine that
honours `Disallow` never requests a trap path, so a hit means the client
either ignored robots.txt or never read it. Leave a trap out of robots.txt and
you are trapping Googlebot.

Trade-offs:
  - Listing a trap in robots.txt advertises the path. A bot that reads
    robots.txt to find interesting URLs walks straight in, which is fine. A bot
    that reads it to stay out also stays out of your traps.
  - Crawl traps say nothing about a scraper that renders the page and follows
    only what a human could click.
  - The site's own link prefetching (Speculation Rules with eager document
    rules, prefetch plugins) can request hidden links for real users. Exclude
    trap URLs from those rules.
"""

TRAP_LINK_PATH = "/catalog/archive"
HONEY_PRODUCT_ID = 13
DECOY_PATHS = {"/.env", "/wp-admin/", "/wp-login.php"}
DECOY_PREFIXES = ("/api/internal/",)

# TODO (Round 3): the search_crawler persona gets trapped at DEFENSE_LEVEL=3.
# It is a well-behaved crawler: it reads robots.txt and obeys every Disallow
# line. Which paths should it be told to stay out of?
ROBOTS_DISALLOW = []


def robots_txt(level):
    lines = ["User-agent: *"]
    if level >= 3:
        lines += [f"Disallow: {path}" for path in ROBOTS_DISALLOW]
    lines.append("Allow: /")
    return "\n".join(lines) + "\n"


def trap_for(path, level):
    """Return the trap name this path triggers at this level, or None."""
    if level < 3:
        return None
    if path == TRAP_LINK_PATH or path.startswith(TRAP_LINK_PATH + "/"):
        return "trap_link"
    if path in (f"/products/{HONEY_PRODUCT_ID}", f"/api/products/{HONEY_PRODUCT_ID}"):
        return "honey_record"
    if path in DECOY_PATHS or path.startswith(DECOY_PREFIXES):
        return "decoy_endpoint"
    return None


def trap_link_html(level):
    """The hidden footer link. Hidden by the .hp class in store.css."""
    if level < 3:
        return ""
    return (f'<a class="hp" href="{TRAP_LINK_PATH}" tabindex="-1" rel="nofollow">'
            "Archived products</a>")


if __name__ == "__main__":
    print("robots.txt at level 3:\n" + robots_txt(3))
    for path in ["/", "/products/2", TRAP_LINK_PATH, f"/api/products/{HONEY_PRODUCT_ID}",
                 "/.env", "/api/internal/export"]:
        print(f"  {path:<24} -> {trap_for(path, 3)}")
