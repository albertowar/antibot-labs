"""Who the well-known crawlers say they are, and how each operator lets you check.

This table is the lab's copy of what each operator documents (October 2026). It is
*given* infrastructure: the rounds change how the gate uses it, not the table.

Three verification styles exist in the wild, and most operators offer only one:

  rdns_suffixes   reverse DNS of the source IP must end in one of these labels, and
                  the forward lookup of that name must return the source IP
                  (Google, Bing, Apple, Amazon).
  ranges          a machine-readable JSON file of IP prefixes the operator publishes
                  (Google, Bing, OpenAI, Anthropic, Perplexity).
  signed          the client signs each request (RFC 9421 / Web Bot Auth) and
                  publishes its keys at a well-known URL (ChatGPT agent, Cloudflare
                  "signed agents"). Handled in defenses/web_bot_auth.py, keyed by
                  the Signature-Agent origin, not by this table.

`category` drives entitlement at DEFENSE_LEVEL >= 3 (see ip_ranges.lane_for):
a *verified* identity is not automatically an *entitled* one. User-triggered
fetchers act for one person and ignore robots.txt, so they get a human's budget,
not a crawler's. `shared_infra` marks ranges/suffixes that belong to rentable
cloud infrastructure (Google App Engine egress is the documented example): a
match proves the network, not the program.

Trade-off: this table is a maintenance burden. Operators add tokens, rename
files and move ranges; a stale copy becomes a false-positive machine. Production
stacks pull these from the operators on a schedule, which is what Round 3 makes
you do for the range files.
"""

from __future__ import annotations

OPERATORS: dict[str, dict] = {
    "googlebot": {
        "ua_tokens": ["Googlebot"],
        "rdns_suffixes": [".googlebot.com", ".google.com"],
        "ranges": ["google/common-crawlers.json"],
        "category": "search-crawler",
        "docs": "https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests",
    },
    "google-fetcher": {
        # User-triggered fetchers (Google-Read-Aloud, FeedFetcher-Google, ...). Google
        # documents two reverse-DNS masks: google-proxy-*.google.com for fetchers Google
        # runs itself and *.gae.googleusercontent.com for fetchers running on customer
        # App Engine apps. The second is shared infrastructure anyone can rent.
        "ua_tokens": ["Google-Read-Aloud", "FeedFetcher-Google", "Google-Site-Verification"],
        "rdns_suffixes": [".google.com", ".googleusercontent.com"],
        "ranges": ["google/user-triggered-fetchers.json"],
        "category": "user-fetcher",
        "shared_infra": True,
        "docs": "https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers",
    },
    "bingbot": {
        "ua_tokens": ["bingbot"],
        "rdns_suffixes": [".search.msn.com"],
        "ranges": ["bing/bingbot.json"],
        "category": "search-crawler",
        "docs": "https://www.bing.com/webmasters/help/verifying-that-bingbot-is-bingbot",
    },
    "applebot": {
        "ua_tokens": ["Applebot"],
        "rdns_suffixes": [".applebot.apple.com"],
        "ranges": [],
        "category": "search-crawler",
        "docs": "https://support.apple.com/en-us/119829",
    },
    "gptbot": {
        "ua_tokens": ["GPTBot"],
        "rdns_suffixes": [],
        "ranges": ["openai/gptbot.json"],
        "category": "ai-training",
        "docs": "https://developers.openai.com/api/docs/bots",
    },
    "oai-searchbot": {
        "ua_tokens": ["OAI-SearchBot"],
        "rdns_suffixes": [],
        "ranges": ["openai/searchbot.json"],
        "category": "ai-search",
        "docs": "https://developers.openai.com/api/docs/bots",
    },
    "chatgpt-user": {
        "ua_tokens": ["ChatGPT-User"],
        "rdns_suffixes": [],
        "ranges": ["openai/chatgpt-user.json"],
        "category": "user-fetcher",
        "docs": "https://developers.openai.com/api/docs/bots",
    },
    "claudebot": {
        # Anthropic publishes one combined list for ClaudeBot, Claude-User and
        # Claude-SearchBot, with no per-bot labels.
        "ua_tokens": ["ClaudeBot", "Claude-User", "Claude-SearchBot"],
        "rdns_suffixes": [],
        "ranges": ["anthropic/bots.json"],
        "category": "ai-training",
        "docs": "https://support.claude.com/en/articles/8896518",
    },
    "perplexitybot": {
        "ua_tokens": ["PerplexityBot"],
        "rdns_suffixes": [],
        "ranges": ["perplexity/perplexitybot.json"],
        "category": "ai-search",
        "docs": "https://docs.perplexity.ai/guides/bots",
    },
}

# Which category earns the crawler budget once the identity is verified. Policy, not
# protocol: a site that sells nothing to AI search can move "ai-search" to anonymous
# (Workshop 4, Chapter 3 is about exactly that decision).
CRAWLER_LANE_CATEGORIES = {"search-crawler", "ai-training", "ai-search"}


def operator_for_range(list_path: str) -> str | None:
    """Reverse lookup: which operator key publishes this range file."""
    for key, op in OPERATORS.items():
        if list_path in op["ranges"]:
            return key
    return None
