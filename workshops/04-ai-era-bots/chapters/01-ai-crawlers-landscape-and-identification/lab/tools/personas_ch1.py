"""
W4 Ch1's cohort: the starter's 40 shoppers plus the nine welcome clients that are not shoppers.

A crawler defense that cannot tell a crawler from a customer is just a block rule. The 40
shoppers (tools/population.py) are the people: home broadband, carrier NAT, consumer VPNs and
a privacy relay, the cohorts a "datacenter address = bot" rule hurts first. Next to them run
nine automated clients you want to keep:

  non-browser (4)     an RSS reader, a Slack link unfurler, an uptime monitor and a developer
                      with curl. Automated, legitimate, and never crawling (a handful of requests).
  declared crawlers   Googlebot and OAI-SearchBot (search), GPTBot and ClaudeBot (training), each
  (5)                 from an address its operator can prove (published ranges, or forward-confirmed
                      reverse DNS for Googlebot), all honouring robots.txt; plus LocalSearchBot, a
                      small search engine that publishes no ranges and no rDNS suffix. It behaves
                      exactly like Googlebot and can never prove it.

Ground-truth labels: shoppers are `human:<persona>:<n>` (the scoreboard counts them as people);
the nine are `legit:<name>:00`, so the scoreboard keeps them out of both "people hurt" and
"bots stopped" and the checkpoint reports them in their own table. Outcomes come from the HTTP
responses: 403 is a stop ("blocked", a false positive), 429 is a budget ("limited", friction you
chose), anything else is served.

Real browsers load the stylesheet, the script and the images of every page they show. The
starter's shoppers are Python and do not, so a PAGE_HOOKS entry below fetches the same static
files a browser would (once, then from cache) through the same client. Without it the Round 3
signature would call every shopper "HTML only".

This module builds the chapter's cohort (personas(), handed to every Round as `people=`) and
registers the `crawl_mix` scenario and the assets PAGE_HOOK; checkpoint.py imports it, so every
round runs these clients.
"""

import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))

import browsers  # noqa: E402
import population  # noqa: E402
from _common import HTML, UA, asset_links, pool_ip  # noqa: E402
from labclient import BASE_URL  # noqa: E402

CRAWL_PAGES = 12

NON_BROWSER = [
    ("rss_reader",     "rss-reader",     ("hosting_asn", 4),  UA["freshrss"], ["/feed.xml"] * 3),
    ("slack_unfurl",   "slack-unfurl",   ("cloud_vm", 56),    UA["slack"],    ["/product/p042"]),
    ("uptime_monitor", "uptime-monitor", ("hosting_asn", 12), UA["uptime"],   ["/health"] * 5),
    ("curl_dev",       "curl-dev",       ("home_fiber", 5),   UA["curl"],     ["/", "/product/p007", "/product/p008"]),
]
# (persona, label, token, rented address). The operators' addresses sit in their published
# snapshots (tools/fixtures/ranges/), except Googlebot's, which is just outside its stale one
# (198.51.100.108; its PTR is in tools/fixtures/dns_zones.json).
CRAWLERS = [
    ("verified_googlebot",     "googlebot",      "Googlebot",      ("cloud_gcp", 11)),
    ("verified_oai_searchbot", "oai-searchbot",  "OAI-SearchBot",  ("cloud_vm", 12)),
    ("verified_gptbot",        "gptbot",         "GPTBot",         ("cloud_vm", 6)),
    ("verified_claudebot",     "claudebot",      "ClaudeBot",      ("cloud_vm", 27)),
    ("localsearchbot",         "localsearchbot", "LocalSearchBot", ("hosting_asn", 5)),
]
_STARTER_PERSONAS = population.personas  # the 40 shoppers; population.personas is left untouched


def personas(seed=population.SEED, n=None):
    people = _STARTER_PERSONAS(seed)
    for p in people:
        p.kind = "shopper"
    for name, label, where, ua, paths in NON_BROWSER:
        p = population.Persona(f"legit:{label}:00", name, ("tool",), pool_ip(*where))
        p.kind, p.ua, p.paths = "tool", ua, paths
        people.append(p)
    for name, label, token, where in CRAWLERS:
        p = population.Persona(f"legit:{label}:00", name, ("tool",), pool_ip(*where))
        p.kind, p.ua, p.token = "crawler", UA[token], token
        people.append(p)
    return people[:n] if n else people


def _verdict(p, client, statuses, **extra):
    """blocked (any 403) > limited (any 429, nothing else wrong) > browsed."""
    outcome = "blocked" if 403 in statuses else ("limited" if 429 in statuses else "browsed")
    p.result.update(outcome=outcome, status=statuses[-1] if statuses else None, requests=client.requests,
                    verdict=client.verdict(), served=statuses.count(200), limited=statuses.count(429),
                    blocked=statuses.count(403), **extra)
    return p.result


def _get(client, p, path):
    client.http.cookies.clear()                       # these clients keep no session
    return client.get(path, headers=[("User-Agent", p.ua), ("Accept", HTML)])


def scenario_tool(p, client, rng):
    statuses = []
    for path in p.paths:
        statuses.append(_get(client, p, path).status_code)
        time.sleep(0.15)
    return _verdict(p, client, statuses)


def scenario_crawler(p, client, rng):
    """A polite crawler: robots.txt first, then the sitemap, only what is allowed."""
    from urllib import robotparser
    rp = robotparser.RobotFileParser()
    rp.parse(_get(client, p, "/robots.txt").text.splitlines())
    paths = re.findall(r"<loc>[^<]*(/product/p\d{3})</loc>", _get(client, p, "/sitemap.xml").text)
    statuses, skipped = [], 0
    for path in paths[:CRAWL_PAGES]:
        if not rp.can_fetch(p.token, path):
            skipped += 1
            continue
        statuses.append(_get(client, p, path).status_code)
        time.sleep(0.03)
    return _verdict(p, client, statuses, skipped=skipped, token=p.token)


def scenario_crawl_mix(p, client, rng):
    kind = getattr(p, "kind", "shopper")
    if kind == "tool":
        return scenario_tool(p, client, rng)
    if kind == "crawler":
        return scenario_crawler(p, client, rng)
    return population.scenario_browse(p, client, rng)


def assets_hook(p, client, response):
    """What a browser does after a page loads: fetch the static files it references (cached after the first page)."""
    if getattr(p, "kind", "shopper") != "shopper" or response.status_code != 200:
        return None
    if "text/html" not in response.headers.get("Content-Type", ""):
        return None
    seen = client.__dict__.setdefault("_seen", set())
    ua = dict(browsers.headers_for(p.browser, "link", BASE_URL)).get("User-Agent", "")
    urls = asset_links(response.text)
    wanted = [u for u in urls if u.startswith("/static/") and (p.js or not u.endswith(".js"))]
    wanted += [u for u in urls if u.startswith("/img/")][:3]
    for u in wanted:
        if u not in seen:
            seen.add(u)
            client.get(u, headers=[("User-Agent", ua), ("Accept", "*/*")])
    return None


population.SCENARIOS["crawl_mix"] = scenario_crawl_mix
if assets_hook not in population.PAGE_HOOKS:
    population.PAGE_HOOKS.append(assets_hook)


def summarize(results):
    """Per-group counts for the checkpoint: people, welcome automation, and who was refused."""
    rows = {}
    for r in results:
        row = rows.setdefault(r["persona"], {"n": 0, "hurt": 0, "limited": 0, "served": 0})
        row["n"] += 1
        row["hurt"] += r.get("outcome") in population.HURT
        row["limited"] += r.get("outcome") == "limited"
        row["served"] += r.get("served", 0)
    return rows
