"""Round 3 defense [STUDENT FILE] — a poisoned maze for crawlers that ignore the rules.

Rounds 1-2 govern crawlers that identify themselves. The stealth crawler does not, so the only
lever left is cost: make every page it fetches worth less and cost more. This is what Nepenthes,
iocaine and Cloudflare's AI Labyrinth do.

The maze has four parts, and each has a cost or a false positive to name:

  1. **Entry link** on every real page: hidden by CSS, `rel="nofollow"`, `tabindex=-1`,
     `aria-hidden`, and under a path that robots.txt Disallows (W1 Ch7: a hit on a Disallowed,
     hidden link means the client ignored the rules or never read them). Browsers never render it;
     prefetchers must be told to skip nofollow/hidden links (the lab's prefetch cohort checks
     exactly that).
  2. **Decoy pages**: deterministic junk text (defenses/babble.py) with LINKS_PER_PAGE links to
     more decoy pages and no way out. `noindex` so a search engine that does wander in does not
     index garbage.
  3. **Tagging**: an IP that fetched >= TAG_AFTER maze pages is tagged for TAG_TTL seconds and gets
     the maze instead of the catalogue. Keyed on IP because that is what the lab has; a crawler
     rotating a large residential pool dilutes this, which is why the budget burn (part 2) matters
     more than the tag, and why production keys on W2-style fingerprints as well.
  4. **Drip delivery** inside a concurrency cap: pages stream slowly to hold the crawler's
     connection, but only MAX_INFLIGHT at a time. Past the cap the store serves the decoy at full
     speed. A tarpit with no cap is a DoS amplifier against yourself (W1 Ch7).

How it reaches the wire: this is not a new verdict (the gate's set is closed). The CHECK below runs
at LADDER[3] and records `ctx.attrs["maze"]` for a tagged client; `demo_site/ext/deterrence.py`
answers it with a decoy page and `g.outcome = "mazed"`, which the scoreboard counts in its own
column. The ext also serves `/maze/<token>` and calls entry_link() on every page.

Defender cost you will see in the checkpoint: generation time per page (sub-ms), bytes served, and
how often the cap was hit.

TODO (Round 3): entry_link() and tagged() below; _token(), record_hit(), render() and the CHECK
are given. Fell behind? python tools/checkpoint.py --round 3 --catch-up
"""

from __future__ import annotations

import hashlib

from . import crawl_policy
from .pipeline import Check, Signal

MAZE_PREFIX = "/maze/"
SECRET = "w4ch3-lab-fixed-secret-not-for-prod"
LINKS_PER_PAGE = 20
TAG_AFTER = 2          # maze pages before the catalogue goes dark for this IP
TAG_TTL = 900          # seconds; IPs get reassigned, so false tags must heal
MAX_INFLIGHT = 8       # concurrent dripped responses, then serve fast
DRIP_CHUNKS = 4
DRIP_DELAY = 0.02      # seconds between chunks (~0.1 s per page)
HITS_KEY = "lab:maze:hits:"      # lab:* so POST /lab/reset forgets every tag


def _token(secret: str, *parts) -> str:
    return hashlib.sha256(":".join([secret, *map(str, parts)]).encode()).hexdigest()[:12]


def entry_link(client_ip: str, secret: str) -> str:
    """TODO (Round 3): the hidden entry link for a real page.

    An <a> to MAZE_PREFIX + _token(secret, "entry", client_ip) (unique per client, so trails are
    attributable) with class="hp", style="display:none", rel="nofollow", tabindex="-1" and
    aria-hidden="true": browsers never show it, polite prefetchers skip it, robots.txt already
    Disallows the prefix. Until then: no entry link, so no crawler ever finds the maze.
    """
    return ""


def record_hit(rds, ip: str) -> int:
    n = rds.incr(f"{HITS_KEY}{ip}")
    rds.expire(f"{HITS_KEY}{ip}", TAG_TTL)
    return int(n)


def tagged(rds, ip: str) -> bool:
    """TODO (Round 3): True once this IP fetched >= TAG_AFTER maze pages (record_hit() keeps the
    counter at HITS_KEY + ip, with TAG_TTL). A tagged client gets the maze instead of the
    catalogue. Until then: never."""
    return False


def render(token: str, babbler, secret: str):
    """Deterministic decoy page: (title, paragraphs, child_tokens)."""
    title, paragraphs, rng = babbler.page(int(token, 16))
    children = [_token(secret, token, i) for i in range(LINKS_PER_PAGE)]
    rng.shuffle(children)
    return title, paragraphs, children


def _check(ctx):
    """Given: a tagged client is answered with the maze instead of the catalogue."""
    if crawl_policy.exempt(ctx.path) or ctx.path.startswith(MAZE_PREFIX):
        return None
    if tagged(ctx.redis, ctx.ip):
        ctx.attrs["maze"] = True
        return [Signal("maze", "tagged", 0, f"{ctx.ip} fetched >= {TAG_AFTER} decoy pages")]
    return None


CHECK = Check("maze", _check)
