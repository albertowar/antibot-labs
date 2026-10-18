"""W4 Ch2's cohort: the starter's 40 shoppers plus eight genuine crawlers.

A verification method only counts if it admits the real thing. The 40 shoppers (tools/population.py)
are the people: home broadband, carrier NAT, consumer VPNs and a privacy relay. The gate does not
apply to browsers, so they measure the price of the shared-gate cost and nothing else; they must
never be hurt. Next to them run eight crawlers that are exactly what they say they are. Each asks
for 60 product pages in a burst, which only the verified lane allows (anonymous = 30, then a
trickle). "Admitted" means all 60 came back 200. They are the false-positive cohort of this chapter:
a verification method an operator does not support, a stale range file, or a signature your proxy
stripped turns a real crawler into a throttled one.

  googlebot      cloud_gcp[0]    PTR crawl-…googlebot.com, forward-confirmed; in common-crawlers.json
  bingbot        cloud_gcp[4]    PTR msnbot-….search.msn.com
  applebot       cloud_gcp[8]    PTR ….applebot.apple.com, publishes no range file
  gptbot         cloud_vm[5]     no PTR; in openai/gptbot.json, in the vendored snapshot too
  gptbot-new     cloud_vm[9]     no PTR; in a prefix OpenAI added after the snapshot
  claudebot      cloud_vm[25]    no PTR; in anthropic/bots.json
  perplexitybot  cloud_vm[31]    no PTR; in perplexity/perplexitybot.json
  chatgpt-agent  cloud_vm[40]    in no list; signs with chatgpt.com's key (Web Bot Auth), covering
                                 @authority, @query and signature-agent, and sends a query string

The chatgpt-agent's query string is deliberate: it carries a percent-escape (`tag=a%20b%2Bc`), so a
verifier that rebuilds the query from parsed arguments instead of the raw string rejects the one
genuine signed agent. That is the recon gap the raw-query enricher closes.

Ground-truth labels: shoppers are `human:<persona>:<n>`; the eight are `legit:<name>:00`, which the
scoreboard keeps out of both "people hurt" and "bots stopped"; the checkpoint reports them in their
own table. A 429 is a budget ("limited": the cost of an unverified identity), a 403 a refusal.

This module provides the chapter cohort (checkpoint.py passes it as Round(people=personas)) and registers the `lane_mix`
scenario; checkpoint.py imports it, so every round runs these clients.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))

import population  # noqa: E402
from _common import HTML, UA, authority, key_of, httpsig  # noqa: E402
from labclient import world_pool  # noqa: E402

CRAWL_PAGES = 60
AGENT_QUERY = "ref=agent&tag=a%20b%2Bc"

# (label, token, (pool, index), signs?)
CRAWLERS = [
    ("googlebot",     "Googlebot",     ("cloud_gcp", 0),  False),
    ("bingbot",       "bingbot",       ("cloud_gcp", 4),  False),
    ("applebot",      "Applebot",      ("cloud_gcp", 8),  False),
    ("gptbot",        "GPTBot",        ("cloud_vm", 5),   False),
    ("gptbot-new",    "GPTBot",        ("cloud_vm", 9),   False),
    ("claudebot",     "ClaudeBot",     ("cloud_vm", 25),  False),
    ("perplexitybot", "PerplexityBot", ("cloud_vm", 31),  False),
    ("chatgpt-agent", "ChatGPT-User",  ("cloud_vm", 40),  True),
]
_STARTER_PERSONAS = population.personas


def personas(seed=population.SEED, n=None):
    people = _STARTER_PERSONAS(seed)
    for label, token, (pool, idx), signs in CRAWLERS:
        p = population.Persona(f"legit:{label}:00", label, ("tool",), world_pool(pool)[idx])
        p.kind, p.ua, p.signs = "crawler", UA[token], signs
        people.append(p)
    return people[:n] if n else people


def scenario_crawler(p, client, rng):
    """60 product pages in a burst. The signing agent signs every request with a fresh nonce."""
    priv = kid = None
    if p.signs:
        priv, _jwk, kid = key_of("chatgpt.com")
    host = authority()
    statuses = []
    for i in range(1, CRAWL_PAGES + 1):
        path = f"/product/p{i:03d}"
        headers = [("User-Agent", p.ua), ("Accept", HTML)]
        if p.signs:
            path += f"?{AGENT_QUERY}"
            mctx = httpsig.MessageContext("GET", host, f"/product/p{i:03d}", {"user-agent": p.ua}, query=AGENT_QUERY)
            headers += list(httpsig.agent_headers(priv, kid, "https://chatgpt.com", mctx,
                                                  components=("@authority", "@query", "signature-agent")).items())
        client.http.cookies.clear()                       # these clients keep no session
        statuses.append(client.get(path, headers=headers).status_code)
    outcome = "blocked" if 403 in statuses else ("limited" if 429 in statuses else "browsed")
    p.result.update(outcome=outcome, status=statuses[-1], requests=client.requests, verdict=client.verdict(),
                    served=statuses.count(200), limited=statuses.count(429), blocked=statuses.count(403))
    return p.result


def scenario_lane_mix(p, client, rng):
    if getattr(p, "kind", "shopper") == "crawler":
        return scenario_crawler(p, client, rng)
    return population.scenario_browse(p, client, rng)


population.SCENARIOS["lane_mix"] = scenario_lane_mix
