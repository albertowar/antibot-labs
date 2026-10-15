"""
Shared plumbing for the four crawler layers of W4 Ch1. Given, not a student exercise.

The chapter turns a stream of catalog requests into a *label* in four steps, and each
step is its own check in the ladder:

    L1  crawler_registry   who does this client SAY it is, and what does robots.txt say to it
    L2  crawler_verify     is the claim true (published ranges, forward-confirmed reverse DNS)
    L3  crawl_signature    does a client that claims nobody behave like a crawler
    L4  crawl_policy       identity x purpose -> allow / limit / challenge / block

The checks pass what they learn to each other in ``ctx.attrs["crawl"]`` (see ``state``)
and this module turns a label into an answer:

  * Rounds 1-3 map labels to allow-or-block with ``default_action``, blunt on purpose:
    it blocks a small search engine that merely cannot prove itself, and it serves a
    verified training crawler as if "verified" meant "welcome".
  * From Round 4 (``ctx.level >= 4``) the earlier layers only label. ``crawl_policy``
    decides, because a hard verdict from L1-L3 would stop the pipeline before the
    policy ever ran.

What it judges. Only the HTML catalog surface (``/``, ``/products``, ``/catalog``,
``/product/<sku>``, ``/search``) is judged. ``/robots.txt``, ``/sitemap.xml``,
``/feed.xml``, the cart, the account pages and ``/api/*`` pass through every layer
unexamined: a crawler must be able to read the policy you want it to follow, and the
JSON API is a separate chapter's problem (W3 Ch2). Static files and images never reach
the gate at all; ``demo_site/ext/crawl.py`` records them for the Round 3 signature.
"""

from __future__ import annotations

import json
import os
import time
from collections import namedtuple

from . import policy
from .pipeline import Signal, Verdict

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data")

# --- The decision vocabulary -----------------------------------------------------
ALLOW, LIMIT, CHALLENGE, BLOCK = "allow", "limit", "challenge", "block"
Decision = namedtuple("Decision", "action reason")

# The identity classes a request is given before the store decides what to do.
BROWSER_LIKE = "browser-like"              # a browser User-Agent, no crawler claim
DECLARED_UNCHECKED = "declared-unchecked"  # claims a known token; nothing verified yet (L1)
DECLARED_VERIFIED = "declared-verified"    # claim confirmed by ranges or FCrDNS (L2)
IMPERSONATOR = "impersonator"              # claim checked and found false (L2)
DECLARED_UNVERIFIABLE = "declared-unverifiable"  # known token, operator publishes no proof (L2)
DECLARED_UNLISTED = "declared-unlisted"    # looks like a bot, token in no registry (L1)
UNDECLARED_CRAWLER = "undeclared-crawler"  # browser UA, crawler behaviour (L3)

CHALLENGE_TYPE = "crawl_proof"             # registered by demo_site/ext/crawl.py


def allow(reason=""):
    return Decision(ALLOW, reason)


def limit(reason):
    return Decision(LIMIT, reason)


def challenge(reason):
    return Decision(CHALLENGE, reason)


def block(reason):
    return Decision(BLOCK, reason)


# --- What kind of request is this -------------------------------------------------
_PAGES = {"/", "/products", "/catalog", "/search"}


def kind_of(path: str) -> str:
    if path.startswith(("/static/", "/img/")):
        return "asset"
    if path == "/robots.txt":
        return "robots"
    if path == "/sitemap.xml":
        return "sitemap"
    if path == "/feed.xml":
        return "feed"
    if path in _PAGES or path.startswith("/product/"):
        return "page"
    return "other"


def sku_of(path: str) -> str | None:
    return path.split("/")[2] or None if path.startswith("/product/") else None


def is_page(ctx) -> bool:
    """True for the requests the crawler layers judge (GET or HEAD on the catalog surface)."""
    return ctx.method in ("GET", "HEAD") and kind_of(ctx.path) == "page"


# --- Per-request state shared by the four checks ----------------------------------

def state(ctx) -> dict:
    """The label under construction for this request (ctx.attrs["crawl"])."""
    return ctx.attrs.setdefault("crawl", {
        "identity": BROWSER_LIKE, "token": "", "purpose": "", "operator": "", "listed": False,
        "robots_ok": True, "method": "", "score": 0.0, "reasons": []})


def default_action(level, identity, robots_ok, score, threshold) -> Decision:
    """What the store does before Round 4 wires a real policy.

    Blunt on purpose: every signal maps to allow or block.
    """
    if level >= 1 and identity != BROWSER_LIKE and not robots_ok:
        return block("robots.txt disallows this token here")
    if level >= 2 and identity == IMPERSONATOR:
        return block("claims a token from an address the operator does not publish")
    if level >= 3:
        if identity == UNDECLARED_CRAWLER:
            return block(f"undeclared crawler (score {score:.0f})")
        if identity in (DECLARED_UNVERIFIABLE, DECLARED_UNLISTED) and score >= threshold:
            return block(f"unverifiable crawler with crawler behaviour (score {score:.0f})")
    return allow("")


def answer(ctx, d: Decision):
    """Turn a Decision into what a Check returns, and put the label in the decision log."""
    st = state(ctx)
    ctx.note(crawl_identity=st["identity"], crawl_token=st["token"], crawl_purpose=st["purpose"],
             crawl_method=st["method"], crawl_score=round(st["score"]), crawl_reason=d.reason,
             crawl_reasons=st["reasons"])
    if d.action == ALLOW:
        return None
    if d.action == LIMIT:           # 429 + Retry-After; the scoreboard counts it as rate_limited
        return Verdict("rate_limit", signals=(Signal("rate_limit", "crawl_budget", 0, d.reason),), retry_after=30)
    if d.action == CHALLENGE:       # the band decides: points sit exactly on the challenge line
        return Verdict("challenge", signals=(Signal("crawl", "challenge", policy.BANDS["challenge"], d.reason),),
                       challenge=CHALLENGE_TYPE)
    return Verdict("block", signals=(Signal("crawl", "block", 100, d.reason),))


def enforce(ctx, threshold=60):
    """Rounds 1-3: the blunt mapping. From Round 4 the earlier layers only label."""
    st = state(ctx)
    if ctx.level >= 4:
        return answer(ctx, allow("labelled; crawl_policy decides"))
    return answer(ctx, default_action(ctx.level, st["identity"], st["robots_ok"], st["score"], threshold))


# --- robots.txt: the policy a crawler is supposed to follow -----------------------
# routes/seo.py serves BASE plus whatever hooks.robots providers return. The registry
# check must evaluate the same text, so both read it from here.
BASE_ROBOTS = ["User-agent: *", "Allow: /", "Disallow: /cart", "Disallow: /checkout",
               "Disallow: /account", "Disallow: /lab/"]
POLICY_FILE = os.path.join(DATA, "crawl_policy.robots")


def policy_lines() -> list[str]:
    """Your lines for robots.txt (data/crawl_policy.robots), read on every call so an edit applies at once."""
    try:
        with open(POLICY_FILE) as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def robots_text() -> str:
    return "\n".join(BASE_ROBOTS + policy_lines()) + "\n"


# --- Per-client request history (written by demo_site/ext/crawl.py) ---------------
HISTORY_WINDOW_S = 900
HISTORY_MAX = 400


def record(redis, ip: str, entry: dict) -> list[dict]:
    """Append to this address's history and return the recent window (oldest first)."""
    key = f"lab:ch1:hist:{ip}"
    redis.rpush(key, json.dumps(entry))
    redis.ltrim(key, -HISTORY_MAX, -1)
    redis.expire(key, HISTORY_WINDOW_S)
    cutoff = time.time() - HISTORY_WINDOW_S
    return [h for h in (json.loads(x) for x in redis.lrange(key, 0, -1)) if h["t"] >= cutoff]


def cluster_key(ua: str, asn: int) -> str:
    import hashlib
    return f"lab:ch1:clus:{hashlib.sha1(ua.encode()).hexdigest()[:10]}:{asn}"


def cluster_add(redis, ua: str, asn: int, sku: str) -> None:
    key = cluster_key(ua, asn)
    redis.sadd(key, sku)
    redis.expire(key, HISTORY_WINDOW_S)


def cluster_share(redis, ua: str, asn: int, catalog_size: int) -> float:
    """Catalog share fetched by all cookie-less clients sharing (User-Agent, ASN).

    One scraper spread over many addresses still shares a client and a network.
    Clients that hold a session cookie are never added: a thousand Chrome users on one
    ISP would otherwise look like one crawler. (Trade-off: a cookie-holding crawler is
    invisible to this signal. That is the Round 3 residual.)
    """
    return redis.scard(cluster_key(ua, asn)) / catalog_size if catalog_size else 0.0


def page_rate(ctx) -> int:
    """This address's catalog page requests in the current minute (counts this one)."""
    key = f"lab:ch1:rate:{ctx.ip}:{int(time.time() // 60)}"
    n = ctx.redis.incr(key)
    ctx.redis.expire(key, 120)
    return int(n)
