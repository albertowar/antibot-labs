"""Round 3 defense (REFERENCE SOLUTION) — a poisoned maze for crawlers that ignore the rules.

Rounds 1-2 govern crawlers that identify themselves. The stealth crawler does
not, so the only lever left is cost: make every page it fetches worth less and
cost more. This is what Nepenthes, iocaine and Cloudflare's AI Labyrinth do.

The maze has four parts, and each has a cost or a false positive to name:

  1. **Entry link** on every real page: hidden by CSS, `rel="nofollow"`,
     `tabindex=-1`, `aria-hidden`, and under a path that robots.txt Disallows
     (W1 Ch7: a hit on a Disallowed, hidden link means the client ignored the
     rules or never read them). Browsers never render it; prefetchers must be
     told to skip nofollow/hidden links (tools/legit_traffic.py's prefetch
     cohort checks exactly that).
  2. **Decoy pages**: deterministic junk text (defenses/babble.py) with
     LINKS_PER_PAGE links to more decoy pages and no way out. `noindex` so a
     search engine that does wander in does not index garbage.
  3. **Tagging**: an IP that fetched >= TAG_AFTER maze pages is tagged for
     TAG_TTL seconds and gets the maze instead of the catalogue. Keyed on IP
     because that is what the lab has; a crawler rotating a large residential
     pool dilutes this, which is why the budget burn (part 2) matters more
     than the tag, and why production keys on W2-style fingerprints as well.
  4. **Drip delivery** inside a concurrency cap: pages stream slowly to hold
     the crawler's connection, but only MAX_INFLIGHT at a time. Past the cap
     the store serves the decoy at full speed. A tarpit with no cap is a DoS
     amplifier against yourself (W1 Ch7).

Defender cost you will see in the checkpoint: generation time per page (sub-ms),
bytes served, and how often the cap was hit.
"""

from __future__ import annotations

import hashlib

MAZE_PREFIX = "/maze/"
LINKS_PER_PAGE = 20
TAG_AFTER = 2          # maze pages before the catalogue goes dark for this IP
TAG_TTL = 900          # seconds; IPs get reassigned, so false tags must heal
MAX_INFLIGHT = 8       # concurrent dripped responses, then serve fast
DRIP_CHUNKS = 4
DRIP_DELAY = 0.02      # seconds between chunks (~0.1 s per page)


def _token(secret: str, *parts) -> str:
    return hashlib.sha256(":".join([secret, *map(str, parts)]).encode()).hexdigest()[:12]


def entry_link(ctx, secret: str) -> str:
    """Hidden entry link for a real page. Unique per client so trails are attributable."""
    tok = _token(secret, "entry", ctx["client_ip"])
    return (f'<a class="hp" href="{MAZE_PREFIX}{tok}" rel="nofollow" tabindex="-1" '
            f'aria-hidden="true">Catalogue archive</a>')


def record_hit(rds, ip: str) -> int:
    n = rds.incr(f"maze:hits:{ip}")
    rds.expire(f"maze:hits:{ip}", TAG_TTL)
    return int(n)


def tagged(rds, ip: str) -> bool:
    return int(rds.get(f"maze:hits:{ip}") or 0) >= TAG_AFTER


def render(token: str, babbler, secret: str):
    """Deterministic decoy page: (title, paragraphs, child_tokens)."""
    title, paragraphs, rng = babbler.page(int(token, 16))
    children = [_token(secret, token, i) for i in range(LINKS_PER_PAGE)]
    rng.shuffle(children)
    return title, paragraphs, children
